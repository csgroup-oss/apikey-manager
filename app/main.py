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
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .controllers import auth_router, example_router, health_router
from .controllers.auth_controller import router_prefix as auth_router_prefix
from .settings import (
    SHOW_APIKEY_ENDPOINTS,
    SHOW_TECHNICAL_ENDPOINTS,
    URL_PREFIX,
    ApiSettings,
    rate_limiter,
)
from .utils.asyncget import SingletonAiohttp

fastAPI_logger = logger  # convenient name

api_settings = ApiSettings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator:
    SingletonAiohttp.get_aiohttp_client()
    yield
    await SingletonAiohttp.close_aiohttp_client()


def get_application() -> FastAPI:
    # For cluster deployment: override the swagger /docs URL from an environment
    # variable. Also set the openapi.json URL under the same path.
    if URL_PREFIX:
        docs_url = URL_PREFIX.strip("/")
        docs_params = {
            "docs_url": f"/{docs_url}",
            "openapi_url": f"/{docs_url}/openapi.json",
        }
    else:
        docs_params = {}

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
            "url": "https://gitlab.si.c-s.fr/space_platforms/sandbox/geojson-proxy",
            "email": "support@csgroup.space",
        },
        root_path=api_settings.root_path,
        openapi_tags=tags_metadata,
        lifespan=lifespan,
        **docs_params,
        redoc_url=None,
        swagger_ui_init_oauth={
            # we use the value passed by env var instead
            "clientId": "(this value is not used)",
            "appName": "API-Key Manager",
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

    # Set and configure rate limiter
    application.state.limiter = rate_limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    application.include_router(
        auth_router,
        prefix=f"{URL_PREFIX}{auth_router_prefix}",
        tags=["Manage API keys"],
        include_in_schema=SHOW_APIKEY_ENDPOINTS,
    )
    application.include_router(
        example_router,
        prefix="/check",
        tags=["Check API keys"],
        include_in_schema=SHOW_TECHNICAL_ENDPOINTS,
    )
    application.include_router(
        health_router,
        prefix="/health",
        tags=["Health"],
        include_in_schema=SHOW_TECHNICAL_ENDPOINTS,
    )

    return application


app = get_application()
