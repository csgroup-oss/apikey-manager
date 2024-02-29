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
import os
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi.security import APIKeyHeader, APIKeyQuery, OpenIdConnect
from jose import jwt
from jose.exceptions import JOSEError
from pydantic import BaseModel
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from ..settings import VERIFY_AUDIENCE
from ..utils.asyncget import SingletonAiohttp
from ._apikey_crud import apikey_crud

LOGGER = logging.getLogger(__name__)

API_KEYS_SHOW_ENDPOINTS = bool(os.environ.get("API_KEYS_SHOW_ENDPOINTS", True))

OAUTH2_METADATA_URL = os.environ.get(
    "OAUTH2_METADATA_URL",
    "https://auth.p3.csgroup.space/realms/METIS/.well-known/openid-configuration",
)


#
# TODO
# - manage referer
# - manage additionnals metadatas
# - manage roles
# - URLS history


router = APIRouter()

oidc = OpenIdConnect(openIdConnectUrl=OAUTH2_METADATA_URL)

public_key_cache: tuple[datetime, tuple[str, str]] | None = None


async def get_issuer_and_public_key() -> tuple[str, str]:
    """Return keycloak URL and public key"""
    global public_key_cache

    if not public_key_cache or public_key_cache[0] < datetime.now():
        issuer = (await SingletonAiohttp.query_url(OAUTH2_METADATA_URL)).get("issuer")
        public_key = (await SingletonAiohttp.query_url(issuer)).get("public_key")
        key = "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"
        public_key_cache = (datetime.now() + timedelta(days=1), (issuer, key))

    return public_key_cache[1]


async def oidc_auth(token: str | None = Depends(oidc)):
    """Return keycloak authentication info"""
    if not token:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
    try:
        issuer, key = await get_issuer_and_public_key()
        return jwt.decode(
            token[7:], key=key, issuer=issuer, options={"verify_aud": VERIFY_AUDIENCE}
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
async def show_my_information(oidc_info: Annotated[dict, Depends(oidc_auth)]):
    return {
        "login": oidc_info["preferred_username"],
        "name": oidc_info.get("name", None),
        "id": oidc_info["sub"],
        "token_creation": datetime.fromtimestamp(oidc_info["auth_time"]),
        "token_expire": datetime.fromtimestamp(oidc_info["exp"]),
        "roles": oidc_info.get("realm_access", {}).get("roles", []),
    }


@router.get("/api_key/new")
async def create_api_key(
    oidc_info: Annotated[dict, Depends(oidc_auth)],
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
        oidc_info["sub"],
        never_expires,
        oidc_info.get("realm_access", {}).get("roles", []),
        config_json,
        allowed_referers,
    )


class UsageLog(BaseModel):
    api_key: str | None = None
    name: str
    is_active: bool
    never_expire: bool
    expiration_date: datetime
    latest_query_date: datetime | None
    total_queries: int
    iam_roles: list | None
    config: dict | None
    allowed_referers: list[str] | None


@router.get(
    "/api_key/list", response_model=list[UsageLog], response_model_exclude_none=True
)
async def list_my_api_keys(
    oidc_info: Annotated[dict, Depends(oidc_auth)]
) -> list[UsageLog]:
    """
    List all API keys and usage information associated with my account.
    """
    # TODO Add some sort of filtering on older keys/unused keys?

    return [
        UsageLog(
            api_key=row[0],
            name=row[1],
            is_active=row[3],
            never_expire=row[4],
            expiration_date=row[5],
            latest_query_date=row[6],
            total_queries=row[7],
            iam_roles=row[8],
            config=row[9],
            allowed_referers=row[10],
        )
        for row in apikey_crud.get_usage_stats(oidc_info["sub"])
    ]


@router.get("/api_key/revoke", dependencies=[Depends(oidc_auth)])
async def revoke_api_key(
    api_key: Annotated[
        str, Query(..., alias="api-key", description="the api_key to revoke")
    ]
) -> None:
    """
    Revoke an API key associated with my account.
    """
    return apikey_crud.revoke_key(api_key)


@router.get("/api_key/renew", dependencies=[Depends(oidc_auth)])
async def renew_api_key(
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
    return apikey_crud.renew_key(api_key, expiration_date)
