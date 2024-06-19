# from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client.apps import StarletteOAuth2App
from fastapi import APIRouter, FastAPI, HTTPException, status
from fastapi.openapi.docs import get_swagger_ui_html
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .. import settings as api_settings
from ..auth.keycloak_util import KCUtil

keycloak: StarletteOAuth2App = None


def init(app: FastAPI) -> APIRouter:
    router = APIRouter()

    domain_url = f"{api_settings.OAUTH2_SERVER_URL}/realms/{api_settings.OAUTH2_REALM}"

    config_data = {
        "KEYCLOAK_CLIENT_ID": api_settings.OAUTH2_CLIENT_ID,
        "KEYCLOAK_CLIENT_SECRET": api_settings.OAUTH2_CLIENT_SECRET,
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
        server_metadata_url=api_settings.OAUTH2_METADATA_URL,
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
        #
        # NOTE: in case of MismatchingStateError, normally this should not happen
        # anymore. It may be a bug in Chrome linked to:
        # https://github.com/encode/starlette/issues/2019
        token = await keycloak.authorize_access_token(request)
        userinfo = dict(token["userinfo"])
        request.session["user"] = userinfo

        # Redirect to this same endpoint to remove the URL query parameters
        return RedirectResponse("docs")

    @router.get("/logout")
    async def logout(request: Request):
        request.session.pop("user", None)
        return {"msg": "Logged out"}

    return router


kcutil = KCUtil()


async def authlib_oauth(request: Request) -> api_settings.AuthInfo:
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
        return api_settings.AuthInfo(
            user_id, user_login, user_info.roles  # type: ignore
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User {user.get('preferred_username')!r} not found in keycloak.",
        )
