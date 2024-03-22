# Copyright 2023, CS GROUP - France, https://www.csgroup.eu/
#
# This file is part of GeojsonProxy project
#     https://gitlab.si.c-s.fr/space_applications/geojsonproxy/
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import json
import logging
import urllib
from datetime import datetime, timedelta
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security
from fastapi.responses import RedirectResponse
from fastapi.security import APIKeyHeader, APIKeyQuery, OAuth2AuthorizationCodeBearer
from jose import jwt
from jose.exceptions import JOSEError
from pydantic import BaseModel
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from ..settings import (
    OAUTH2_CLIENT_ID,
    OAUTH2_METADATA_URL,
    SHOW_TECHNICAL_ENDPOINTS,
    URL_PREFIX,
    VERIFY_AUDIENCE,
)
from ..utils.asyncget import SingletonAiohttp
from ._apikey_crud import apikey_crud

LOGGER = logging.getLogger(__name__)

#
# TODO
# - manage referer
# - manage additionnals metadatas
# - manage roles
# - URLS history


router = APIRouter()
router_prefix = "/auth"  # TODO: put in settings ?


def oauth2_endpoint(endpoint: str) -> str:
    """Get endpoints for oauth2 authentication"""
    response = httpx.get(OAUTH2_METADATA_URL)
    response.raise_for_status()
    return response.json().get(endpoint)


authorization_endpoint = None


def get_authorization_endpoint():
    """Init and return the authorization endpoint url."""

    # TODO: add a thread lock to be sure to execute only once ?

    global authorization_endpoint
    if authorization_endpoint:
        return authorization_endpoint

    print(  # TODO use logger # noqa: T201
        f"Connecting to the keycloak server {OAUTH2_METADATA_URL!r} ..."
    )
    authorization_endpoint = oauth2_endpoint("authorization_endpoint")
    print("Connected to the keycloak server")  # TODO use logger # noqa: T201
    return authorization_endpoint


# See: https://developer.zendesk.com/api-reference/sales-crm/authentication/requests/
# Authorization Code Flow - Three Legged - is the most secure authentication flow,
# and should be utilized when possible.
# oauth2 = OAuth2AuthorizationCodeBearer(
#     authorizationUrl=authorization_endpoint, tokenUrl=token_endpoint
# )


# In our case we don't want the user to know the client secret so we use the implicit
# flow (Two Legged) instead which does not use the client secret.
# The client id is passed by environment variable.
# The fastapi oauth2 implementation doens not define (as v0.110.0) an implicit
# implementation so we just override OAuth2AuthorizationCodeBearer and change
# the flow manually.
class OAuth2Implicit(OAuth2AuthorizationCodeBearer):
    def __init__(self, *args, **kwargs):
        # No token url overriding with the 'implicit' flow
        super().__init__(*args, **kwargs, tokenUrl="")

        self.model.flows.implicit = self.model.flows.authorizationCode
        self.model.flows.authorizationCode = None


# Use this implementation, override the authorization url to use our custom endpoint
# that is defined just below.
oauth2 = OAuth2Implicit(authorizationUrl=f"{URL_PREFIX}{router_prefix}/auth")


@router.get("/auth", include_in_schema=SHOW_TECHNICAL_ENDPOINTS)
async def custom_authorization(request: Request):
    """Custom endpoint to override the authorization url to the oauth2 server."""

    # Read the request query params, override the client id to use the
    # value passed by environment variable
    params = dict(request.query_params)
    params["client_id"] = OAUTH2_CLIENT_ID

    # Get request to the authorization url
    return RedirectResponse(
        f"{get_authorization_endpoint()}?{urllib.parse.urlencode(params)}"  # type: ignore # noqa: E501
    )


public_key_cache: tuple[datetime, tuple[str, str]] | None = None


async def get_issuer_and_public_key() -> tuple[str, str]:
    """Return oauth2 URL and public key"""
    global public_key_cache

    if not public_key_cache or public_key_cache[0] < datetime.now():
        issuer = (await SingletonAiohttp.query_url(OAUTH2_METADATA_URL)).get("issuer")
        public_key = (await SingletonAiohttp.query_url(issuer)).get("public_key")
        key = "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"
        public_key_cache = (datetime.now() + timedelta(days=1), (issuer, key))

    return public_key_cache[1]


async def oauth2_login(token: str | None = Depends(oauth2)):
    """Return oauth2 authentication info"""
    if not token:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
    try:
        issuer, key = await get_issuer_and_public_key()
        return jwt.decode(
            # token[7:],  # remove the "Bearer " header
            token,
            key=key,
            issuer=issuer,
            options={"verify_aud": VERIFY_AUDIENCE},
        )
    except JOSEError as e:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=str(e))


api_key_query = APIKeyQuery(
    name="api-key", scheme_name="API key query", auto_error=False
)
api_key_header = APIKeyHeader(
    name="x-api-key", scheme_name="API key header", auto_error=False
)


async def api_key_security(
    query_param: Annotated[str, Security(api_key_query)],
    header_param: Annotated[str, Security(api_key_header)],
):
    if not query_param and not header_param:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="An API key must be passed as query or header",
        )

    key_info = apikey_crud.check_key(query_param or header_param)

    if key_info:
        return key_info
    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Wrong, revoked, or expired API key."
        )


@router.get("/me")
async def show_my_information(oauth2_info: Annotated[dict, Depends(oauth2_login)]):
    return {
        "login": oauth2_info["preferred_username"],
        "name": oauth2_info.get("name", None),
        "id": oauth2_info["sub"],  # sub = id of the subject
        "token_creation": datetime.fromtimestamp(oauth2_info["auth_time"]),
        "token_expire": datetime.fromtimestamp(oauth2_info["exp"]),
        "roles": oauth2_info.get("realm_access", {}).get("roles", []),
    }


@router.get("/api_key/new")
async def create_api_key(
    oauth2_info: Annotated[dict, Depends(oauth2_login)],
    name: Annotated[
        str,
        Query(
            description="set API key name",
        ),
    ],
    never_expires: Annotated[
        bool,
        Query(
            description="if set, the created API key will never be considered expired",
        ),
    ] = False,
    config: Annotated[
        str,
        Query(
            description="Allowed hosts that can use this API Key",
        ),
    ] = "{}",
    allowed_referers: Annotated[
        list[str] | None,
        Query(
            description="Allowed hosts that can use this API Key",
        ),
    ] = None,
) -> str:
    """
    Create and return a new API key associated with my account.
    """
    config_json = json.loads(config)
    return apikey_crud.create_key(
        name,
        oauth2_info["sub"],
        oauth2_info["preferred_username"],
        never_expires,
        oauth2_info.get("realm_access", {}).get("roles", []),
        config_json,
        allowed_referers,
    )


class UsageLog(BaseModel):
    api_key: str | None = None
    name: str
    user_login: str
    is_active: bool
    never_expire: bool
    expiration_date: datetime
    latest_query_date: datetime | None
    total_queries: int
    latest_sync_date: datetime | None
    iam_roles: list | None
    config: dict | None
    allowed_referers: list[str] | None


@router.get(
    "/api_key/list", response_model=list[UsageLog], response_model_exclude_none=True
)
async def list_my_api_keys(
    oauth2_info: Annotated[dict, Depends(oauth2_login)]
) -> list[UsageLog]:
    """
    List all API keys and usage information associated with my account.
    """
    # TODO Add some sort of filtering on older keys/unused keys?

    return [
        UsageLog(
            api_key=row[0],
            name=row[1],
            user_login=row[3],
            is_active=row[4],
            never_expire=row[5],
            expiration_date=row[6],
            latest_query_date=row[7],
            total_queries=row[8],
            latest_sync_date=row[9],
            iam_roles=row[10],
            config=row[11],
            allowed_referers=row[12],
        )
        for row in apikey_crud.get_usage_stats(oauth2_info["sub"])
    ]


@router.get("/api_key/revoke")
async def revoke_api_key(
    oauth2_info: Annotated[dict, Depends(oauth2_login)],
    api_key: Annotated[
        str, Query(..., alias="api-key", description="the api_key to revoke")
    ],
) -> None:
    """
    Revoke an API key associated with my account.
    """
    return apikey_crud.revoke_key(oauth2_info["sub"], api_key)


@router.get("/api_key/renew")
async def renew_api_key(
    oauth2_info: Annotated[dict, Depends(oauth2_login)],
    api_key: Annotated[
        str, Query(..., alias="api-key", description="the API key to renew")
    ],
    expiration_date: Annotated[
        str | None,
        Query(
            alias="expiration-date",
            description="the new expiration date in ISO format",
        ),
    ] = None,
) -> str | None:
    """
    Renew an API key associated with my account, reactivate it if it was revoked.
    """
    return apikey_crud.renew_key(oauth2_info["sub"], api_key, expiration_date)
