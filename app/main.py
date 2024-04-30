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

import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.logger import logger
from fastapi.middleware.cors import CORSMiddleware

from .controllers import auth_router, health_router, test_router
from .settings import ApiSettings
from .utils.asyncget import SingletonAiohttp

fastAPI_logger = logger  # convenient name

api_settings = ApiSettings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator:
    SingletonAiohttp.get_aiohttp_client()
    yield
    await SingletonAiohttp.close_aiohttp_client()


def get_application() -> FastAPI:
    tags_metadata = [
        {
            "name": "apikeymanager",
            "description": "Operations with users. The **login** logic is also here.",
        },
    ]

    application = FastAPI(
        title=api_settings.name,
        description="APIKeyManager is a centralized Python-oriented API Key manager.",
        version="1.0.0",
        contact={
            "name": "Gaudissart Vincent - CS Group",
            "url": "https://github.com/CS-SI/apikeymanager",
            "email": "support@csgroup.space",
        },
        docs_url="/docs/",
        root_path=api_settings.root_path,
        openapi_tags=tags_metadata,
        lifespan=lifespan,
        redoc_url=None,
        swagger_ui_init_oauth={
            "clientId": "fastapi_test",
            "appName": "Doc Tools",
            "usePkceWithAuthorizationCodeGrant": True,
            "scopes": "openid profile",
        },
    )

    apikey_pattern = re.compile(r"k\/([-a-z0-9]+)\/")

    @application.middleware("http")
    async def apikeyinpath_mdware(request: Request, call_next: Callable) -> Callable:
        """FastAPI middleware that enable api-key retrieving through the
        `/k/<api-key>/<route>` pattern.
        """
        if "/k/" in request.url.path:
            match = apikey_pattern.search(request.url.path)
            if match:
                apikey = match.group(1)
                # Modify root_path so `url_for` queries will add api-key in path
                request.scope["root_path"] = request.scope["root_path"] + "/k/" + apikey
                # Remove api-key from path for Route resolution
                striplen = len(request.scope["root_path"])
                request.scope["path"] = request.url.path[striplen:]
                # Add api-key in header to use it to secure route
                request.headers.__dict__["_list"].append(
                    (
                        b"x-api-key",
                        bytes(apikey, "ascii"),
                    )
                )

        # Manually handle "x-forwarded-host"
        xforwardedhost = request.headers.get("x-forwarded-host")
        if xforwardedhost and xforwardedhost != request.headers.get("host"):
            # Replace header in place
            for i, v in enumerate(request.headers.__dict__["_list"]):
                if v[0] == b"host":
                    request.headers.__dict__["_list"][i] = (
                        b"host",
                        xforwardedhost.encode(),
                    )
                    break

        return await call_next(request)

    application.add_middleware(
        CORSMiddleware,
        allow_origin_regex=api_settings.cors_origins_regex,
        allow_credentials=True,
        allow_methods=api_settings.cors_allow_methods,
        allow_headers=["*"],
    )

    application.include_router(health_router, prefix="/health", tags=["health"])
    application.include_router(auth_router, prefix="/auth", tags=["_auth"])
    application.include_router(test_router, prefix="/test", tags=["test"])

    return application


app = get_application()
