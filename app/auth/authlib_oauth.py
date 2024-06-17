from fastapi import APIRouter, FastAPI, Depends, HTTPException, status
# from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client.apps import StarletteOAuth2App
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from fastapi.openapi.docs import get_swagger_ui_html
from authlib.integrations.base_client.errors import MismatchingStateError
import os
from .keycloak_util import KCUtil
 
from fastapi import FastAPI
# from fastapi.logger import logger
 
# from app.router import router as http_router

from ..settings import AuthInfo, api_settings

PREFIX = "" #"/authlib/oauth"

keycloak: StarletteOAuth2App = None

def init(app: FastAPI) -> APIRouter:

    router = APIRouter()

    config_data = {
        'KEYCLOAK_CLIENT_ID': api_settings.oidc_client_id,
        'KEYCLOAK_CLIENT_SECRET': api_settings.oidc_client_secret,
        'KEYCLOAK_DOMAIN_URL': f"{api_settings.oidc_endpoint}/realms/{api_settings.oidc_realm}",
    }
    
    config = Config(environ=config_data)

    app.add_middleware(SessionMiddleware, secret_key='!secret')
    
    oauth = OAuth(config)

    global keycloak
    keycloak = oauth.register(
        'keycloak',
        client_id=config('KEYCLOAK_CLIENT_ID'),
        client_secret=config('KEYCLOAK_CLIENT_SECRET'),
        server_metadata_url=api_settings.oidc_metadata_url,
        client_kwargs={
            'scope': 'openid profile email',
        },
    )
 
    @router.get("/docs", include_in_schema=False)
    async def custom_swagger_ui_html(request: Request):
        """
        Override the Swagger /docs endpoint so the user must login with keycloak 
        before displaying the Swagger UI.
        """
        # If the user is already logged in, do nothing, just display the Swagger UI.
        if request.session.get('user'):
            nonlocal app
            return get_swagger_ui_html(openapi_url=app.openapi_url, title=app.title + " - Swagger UI")
        
        # Else log the user in
        return RedirectResponse(url='/login')
    
    @router.get('/login', include_in_schema=False)
    async def login(request: Request):
        """
        Login with keycloak.
        NOTE: Don't call this endpoint from Swagger, it won't work because of the redirection to keycloak.
        """
        # If the user is already logged in, we redirect to /docs to display the Swagger UI.
        if request.session.get('user'):
            return RedirectResponse(url='/docs')
        
        # Else do the authentication with keycloak.
        # We redirect to the /auth endpoint implemented below.
        redirect_uri = request.url_for("auth") 
        return await keycloak.authorize_redirect(request, redirect_uri)
    
    @router.get('/auth', include_in_schema=False)
    async def auth(request: Request):
        """NOTE: don't call this endpoint directly. It is called by the /login endpoint."""

        # With the OAuth2 authentication, the endpoint /login calls keycloak which then call /auth.
        # We save the user information received from keycloak.
        try:
            token = await keycloak.authorize_access_token(request)
        except MismatchingStateError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"msg": f"This is a bug from Chome. Try in a private window or with Firefox."})

        userinfo = dict(token['userinfo'])
        request.session['user'] = userinfo

        # Then we redirect to /docs to display the Swagger UI.
        return RedirectResponse(url='/docs')
    
    @router.get('/logout')
    async def logout(request: Request):
        request.session.pop('user', None)
        return {'msg': 'Logged out'}
    
    @router.get('/protected', include_in_schema=api_settings.show_technical_endpoints)
    async def protected_route(user: dict = Depends(authlib_oauth)):
        return {'msg': 'You are logged in', 'user': user}
    
    return router

kcutil = KCUtil()

async def authlib_oauth(request: Request) -> AuthInfo:
        
    user = request.session.get('user')
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail={"msg": f"You are not logged in. Refresh this page with F5 to log in or go to: {request.base_url}docs"})
    
    user_id = user.get("sub")
    keycloak_user_info = kcutil.get_user_info(user_id)
    return AuthInfo(user_id, keycloak_user_info.roles)
