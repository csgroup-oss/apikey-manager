# Copyright 2023-2024, CS GROUP - France, https://www.csgroup.eu/
#
# This file is part of APIKeyManager project
#     https://gitlab.si.c-s.fr/space_applications/apikeymanager/
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
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Security
from pydantic import BaseModel

from ..settings import rate_limiter
from .auth_controller import api_key_header, api_key_query, api_key_security

LOGGER = logging.getLogger(__name__)

router = APIRouter()


class CheckKey(BaseModel):
    user_login: str
    iam_roles: list | None
    config: dict | None


@router.get("/api_key", response_model=CheckKey)
@rate_limiter.limit("20/minute")
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


@router.get("/test")
def some_test(
    request: Request, api_key_info: Annotated[dict, Depends(api_key_security)]
):
    """
    For internal testing only, check an API key validity and
    return corresponding info.
    """
    return {
        "api_key_info": api_key_info,
        "request.url": request.url,
        "request['headers']": request["headers"],
        "request.client": request.client,
        "request.url_for": request.url_for("some_test"),
        "request.root_path": request.scope.get("root_path"),
        "request.scope": [{i[0]: str(i[1])} for i in request.scope.items()],
    }
