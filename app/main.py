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

import re
from collections.abc import Callable

import uvicorn
from fastapi import FastAPI, Request
from fastapi.logger import logger
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .auth import authlib_oauth
from .controllers import auth_router, example_router, health_router
from .settings import api_settings, rate_limiter

fastAPI_logger = logger  # convenient name


def get_application() -> FastAPI:
    # tags_metadata = [
    #     {
    #         "name": "apikeymanager",
    #         "description": "Operations with users. The **login** logic is also here.",
    #     },
    # ]
    tags_metadata = None

    application = FastAPI(
        title=api_settings.name,
        description=api_settings.swagger_description,
        version="1.0.0",
        contact={
            "name": "CS Group France",
            "url": "https://github.com/csgroup-oss/apikey-manager/",
            "email": "support@csgroup.space",
        },
        openapi_url=api_settings.openapi_url,
        # If we use the authlib OAuth authentication, we override the /docs endpoint.
        # Here we must pass None so the URLs /docs and /docs/ (with a trailing slash)
        # are both redirected to our endpoint.
        docs_url=None if api_settings.use_authlib_oauth else "/docs/",
        root_path=api_settings.root_path,
        openapi_tags=tags_metadata,
        redoc_url=None,
        swagger_ui_init_oauth={
            "clientId": api_settings.oidc_client_id,
            "appName": api_settings.name,
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

    application.include_router(auth_router, prefix="/auth", tags=["Manage API keys"])
    application.include_router(
        health_router,
        prefix="/health",
        tags=["Health"],
        include_in_schema=api_settings.show_technical_endpoints,
    )

    # Don't use the OpenIdConnect authentication.
    # Use the authlib OAuth authentication instead.
    if api_settings.use_authlib_oauth:
        authlib_oauth_router = authlib_oauth.init(application)

        application.include_router(
            authlib_oauth_router,
            tags=["authlib OAuth"],
            include_in_schema=api_settings.show_technical_endpoints,
        )

    if api_settings.debug:
        application.include_router(
            example_router,
            prefix="/example",
            tags=["Example of protected service"],
            include_in_schema=api_settings.show_technical_endpoints,
        )
    return application


app = get_application()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9999, log_config="log_config.yaml")
