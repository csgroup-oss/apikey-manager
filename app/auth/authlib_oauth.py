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
from fastapi.responses import HTMLResponse
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from fastapi import FastAPI, Request, Response


from ..settings import AuthInfo, api_settings
from .keycloak_util import KCUtil

keycloak: StarletteOAuth2App = None

# See https://github.com/fastapi/fastapi/discussions/7817#discussioncomment-5144391
class RequiresLoginException(Exception):
    pass    


async def is_logged_in(request: Request) -> bool:
    return "user" in request.session

async def login(request: Request):
    """
    Override the Swagger /docs endpoint so the user must login with keycloak
    before displaying the Swagger UI.
    """
    calling_endpoint = request.url
    called_from_console = (calling_endpoint.path.rstrip("/") == "/login_from_console")

    # If the user is already logged in
    if await is_logged_in(request):

        if called_from_console:
            return HTMLResponse("You are logged in.")
    
        # If the login endpoint was called from the browser, redirect to the Swagger UI
        if calling_endpoint.path.rstrip("/") == "/login_from_browser":
            return RedirectResponse(request.app.docs_url)

        # For other endpoints called from the browser, redirect to this endpoint
        return RedirectResponse(calling_endpoint)

    # Code and state coming from keycloak
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    # If they are not set, then we need to call keycloak,
    # which then will call again this endpiont.
    if (not code) and (not state):
        response = await keycloak.authorize_redirect(request, calling_endpoint)

        # If called from a console, return the login page url so the caller can display it itself.
        if called_from_console:
            return response.headers["location"]

        # From a browser, make the redirection in the current browser tab
        return response

    # Else we are called from keycloak.
    # We save in cookies the user information received from keycloak.
    token = await keycloak.authorize_access_token(request)
    userinfo = dict(token["userinfo"])
    request.session["user"] = userinfo

    # Redirect to the calling endpoint after removing the authentication query parameters from the URL.
    # See: https://stackoverflow.com/a/7734686
    url = urlparse(str(calling_endpoint))
    query = parse_qs(url.query, keep_blank_values=True)
    for param in ['state', 'session_state', 'iss', 'code']:
        query.pop(param, None)
    url = url._replace(query=urlencode(query, True))
    return RedirectResponse(urlunparse(url))


def init(app: FastAPI) -> APIRouter:
    router = APIRouter()

    domain_url = f"{api_settings.oidc_endpoint}/realms/{api_settings.oidc_realm}"

    config_data = {
        "KEYCLOAK_CLIENT_ID": api_settings.oidc_client_id,
        "KEYCLOAK_CLIENT_SECRET": api_settings.oidc_client_secret,
        "KEYCLOAK_DOMAIN_URL": domain_url,
    }

    config = Config(environ=config_data)

    app.add_middleware(SessionMiddleware, secret_key=api_settings.cookie_secret)

    oauth = OAuth(config)

    global keycloak
    keycloak = oauth.register(
        "keycloak",
        client_id=config("KEYCLOAK_CLIENT_ID"),
        client_secret=config("KEYCLOAK_CLIENT_SECRET"),
        server_metadata_url=api_settings.oidc_metadata_url,
        client_kwargs={
            "code_challenge_method": "S256", # Add PKCE for Authorization Code
            "scope": "openid profile email",
        },
    )

    @router.get("/is_logged_in", include_in_schema=False)
    async def is_logged_in_endpoint(request: Request) -> bool:
        return await is_logged_in(request)

    @router.get("/login_from_browser", include_in_schema=False)
    async def login_from_browser(request: Request):
        return await login(request)

    @router.get("/login_from_console", include_in_schema=False)
    async def login_from_console(request: Request):
        return await login(request)

    @app.exception_handler(RequiresLoginException)
    async def exception_handler(request: Request, exc: RequiresLoginException) -> Response:
        return await login(request)

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
    



    from fastapi import Depends
    from typing import Annotated
    from pydantic import BaseModel
    class Item(BaseModel):
        name: str
        description: str | None = None
        price: float
        tax: float | None = None
    @router.post("/test_post")
    async def test_post(
        auth_info: Annotated[AuthInfo, Depends(authlib_oauth)],
        item: Item
    ) -> str | None:
        bp = 0



    return router


kcutil = KCUtil()

    


async def authlib_oauth(request: Request) -> AuthInfo:
    # Read user information from cookies to see if he's logged in
    user = request.session.get("user")
    if not user:

        # We can login then redirect to this endpoint, but this is not possible to make redirection from the Swagger.
        # In this case, referer = http://<domain>:<port>/docs
        referer = request.headers.get("referer")
        if referer and (urlparse(referer).path.rstrip("/") == request.app.docs_url):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, 
                f"You must first login by calling this URL in your browser: {request.url_for('login_from_browser')}")
        
        # Let's hope that the caller called from a browser (can we detect this ?) or the redirections won't work.
        # Raising this exception will call the login method and redirect.        
        raise RequiresLoginException

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

