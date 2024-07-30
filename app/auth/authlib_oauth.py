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

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client.apps import StarletteOAuth2App
from fastapi import APIRouter, FastAPI, HTTPException, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from ..settings import AuthInfo, api_settings
from .keycloak_util import KCUtil

keycloak: StarletteOAuth2App = None


def init(app: FastAPI) -> APIRouter:
    router = APIRouter()

    domain_url = f"{api_settings.oidc_endpoint}/realms/{api_settings.oidc_realm}"

    config_data = {
        "KEYCLOAK_CLIENT_ID": api_settings.oidc_client_id,
        "KEYCLOAK_CLIENT_SECRET": api_settings.oidc_client_secret,
        "KEYCLOAK_DOMAIN_URL": domain_url,
    }

    config = Config(environ=config_data)

    app.add_middleware(SessionMiddleware, secret_key="!secret")

    oauth = OAuth(config)

    global keycloak
    keycloak = oauth.register(
        "keycloak",
        client_id=config("KEYCLOAK_CLIENT_ID"),
        client_secret=config("KEYCLOAK_CLIENT_SECRET"),
        server_metadata_url=api_settings.oidc_metadata_url,
        client_kwargs={
            "scope": "openid profile email",
        },
    )

    @router.get("/docs", include_in_schema=False)
    async def docs(request: Request):
        """
        Override the Swagger /docs endpoint so the user must login with keycloak
        before displaying the Swagger UI.
        """
        nonlocal app
        ui_title = app.title + " - Swagger UI"

        # If the user is already logged in, do nothing, just display the Swagger UI.
        if request.session.get("user"):
            return get_swagger_ui_html(openapi_url=app.openapi_url, title=ui_title)

        # Code and state coming from keycloak
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        # If they are not set, then we need to call keycloak,
        # which then will call again this endpiont.
        if (not code) and (not state):
            redirect_uri = request.url_for("docs")
            return await keycloak.authorize_redirect(request, redirect_uri)

        # Else we are called from keycloak.
        # We save the user information received from keycloak.
        token = await keycloak.authorize_access_token(request)
        userinfo = dict(token["userinfo"])
        request.session["user"] = userinfo

        # Redirect to this same endpoint to remove the URL query parameters
        return RedirectResponse("docs")

    @router.get("/logout")
    async def logout(request: Request):
        request.session.pop("user", None)

        for key in list(request.session.keys()):
            if key.startswith("_state_"):
                request.session.pop(key, None)

        metadata = await keycloak.load_server_metadata()
        end_session_endpoint = metadata["end_session_endpoint"]

        return HTMLResponse(
            "You are logged out.<br><br>"
            "Click here to also log out from the authentication server: "
            f"<a href='{end_session_endpoint}' target='_blank'>"
            f"{end_session_endpoint}</a>"
        )

    return router


kcutil = KCUtil()


async def authlib_oauth(request: Request) -> AuthInfo:
    # Read user information from cookies
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "msg": "You are not logged in. "
                f"Refresh this page with F5 to log in or go to: {request.base_url}docs"
            },
        )

    user_id = user.get("sub")
    user_login = user.get("preferred_username")
    user_info = kcutil.get_user_info(user_id)

    if user_info.is_enabled:
        return AuthInfo(user_id, user_login, user_info.roles)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User {user_login!r} not found in keycloak.",
        )
