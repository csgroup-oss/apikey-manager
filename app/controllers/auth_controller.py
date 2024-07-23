# Copyright 2023-2024, CS GROUP - France, https://www.csgroup.eu/
#
# This file is part of APIKeyManager project
#     https://github.com/csgroup-oss/apikey-manager/
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


import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated

import aiohttp
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security
from fastapi.security import APIKeyHeader, APIKeyQuery, OpenIdConnect
from jose import jwt
from jose.exceptions import JOSEError
from pydantic import BaseModel, Json
from pydantic.json_schema import SkipJsonSchema
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from ..auth.apikey_crud import apikey_crud
from ..settings import api_settings, rate_limiter

LOGGER = logging.getLogger(__name__)


#
# TODO
# - URLS history

router = APIRouter()


oidc = OpenIdConnect(openIdConnectUrl=api_settings.oidc_metadata_url)

public_key_cache: tuple[datetime, tuple[str, str]] | None = None


@dataclass
class AuthInfo:
    user_id: str
    roles: list[str]


async def get_issuer_and_public_key() -> tuple[str, str]:
    global public_key_cache

    if not public_key_cache or public_key_cache[0] < datetime.now():
        async with aiohttp.ClientSession() as session:
            async with session.get(api_settings.oidc_metadata_url) as resp:
                issuer = (await resp.json()).get("issuer")
            async with session.get(issuer) as resp:
                public_key = (await resp.json()).get("public_key")

        key = "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----"
        public_key_cache = (datetime.now() + timedelta(days=1), (issuer, key))

    return public_key_cache[1]


async def oidc_auth(token: str | None = Depends(oidc)) -> AuthInfo:
    if not token:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
    try:
        issuer, key = await get_issuer_and_public_key()
        if token.startswith("Bearer "):
            token = token[7:]  # remove the "Bearer " header

        decoded = jwt.decode(
            token, key=key, issuer=issuer, audience=api_settings.oidc_client_id
        )
        return AuthInfo(decoded.get("sub"), decoded.get("roles"))
    except JOSEError as e:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=str(e))


async def main_auth():
    if api_settings.auth_function:
        return api_settings.auth_function
    else:
        return oidc_auth


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
async def show_me(auth_info: Annotated[AuthInfo, Depends(oidc_auth)]):
    return {"user_id": auth_info.user_id, "roles": auth_info.roles}


@router.get("/api_key/new")
def get_new_api_key(
    auth_info: Annotated[AuthInfo, Depends(oidc_auth)],
    name: Annotated[
        str,
        Query(
            description="set API key name",
        ),
    ],
    config: Annotated[
        Json,
        Query(
            description="Free JSON object that can be used to configure services",
        ),
    ],
    allowed_referers: Annotated[
        list[str] | SkipJsonSchema[None],
        Query(description="Allowed hosts that can use this API Key"),
    ] = None,
    never_expires: Annotated[
        bool,
        Query(
            description="if set, the created API key will never be considered expired",
        ),
    ] = False,
) -> str:
    """
    Returns:
        api_key: a newly generated API key
    """
    return apikey_crud.create_key(
        name,
        auth_info.user_id,
        never_expires,
        auth_info.roles,
        config,
        allowed_referers,
    )


@router.get("/api_key/revoke")
async def revoke_api_key(
    auth_info: Annotated[AuthInfo, Depends(oidc_auth)],
    api_key: Annotated[
        str, Query(..., alias="api-key", description="the api_key to revoke")
    ],
) -> None:
    """
    Revoke an API key associated with my account.
    """
    return apikey_crud.revoke_key(auth_info.user_id, api_key)


@router.get("/api_key/renew")
async def renew_api_key(
    auth_info: Annotated[AuthInfo, Depends(oidc_auth)],
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
    return apikey_crud.renew_key(auth_info.user_id, api_key, expiration_date)


class UsageLog(BaseModel):
    api_key: str | None = None
    name: str
    user_active: bool
    is_active: bool
    never_expire: bool
    expiration_date: datetime
    latest_query_date: datetime | None
    total_queries: int
    latest_sync_date: datetime | None
    iam_roles: list[str] | None
    config: dict | None
    allowed_referers: list[str] | None


@router.get(
    "/api_key/list",
    response_model=list[UsageLog],
    response_model_exclude_none=True,
)
def get_api_key_usage_logs(
    auth_info: Annotated[AuthInfo, Depends(oidc_auth)]
) -> list[UsageLog]:
    """
    Returns usage information for all API keys
    """
    # TODO Add some sort of filtering on older keys/unused keys?

    return [
        UsageLog(
            api_key=row[0],
            name=row[1],
            user_active=row[3],
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
        for row in apikey_crud.get_usage_stats(auth_info.user_id)
    ]


class CheckKey(BaseModel):
    user_id: str
    iam_roles: list | None
    config: dict | None


def custom_rate_limiter(func):
    """Customize the rate_limiter depending on our configuration."""
    # If the env variable is not defined, don't use a rate limiter
    if not api_settings.rate_limit:
        return func
    # Else return the check_api_key function decorated with
    # the rate_limiter configured with our setting
    return rate_limiter.limit(api_settings.rate_limit)(func)


@router.get("/check_key", response_model=CheckKey)
@custom_rate_limiter
async def check_api_key(
    request: Request,  # needed by the rate limiter
    query_param: Annotated[str, Security(api_key_query)],
    header_param: Annotated[str, Security(api_key_header)],
):
    """
    Check an API KEY validity in the database.
    \f
    Todo:
        * Synchronize database with keycloak.
    """
    return await api_key_security(query_param, header_param)
