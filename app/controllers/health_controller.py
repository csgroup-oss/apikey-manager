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

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

LOGGER = logging.getLogger(__name__)

router = APIRouter()


@router.get("/status", response_model=str, name="check user health microservice")
async def status_check(request: Request) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_200_OK, content={"healthy": True})
