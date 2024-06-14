from fastapi import APIRouter, FastAPI, Depends, HTTPException, status
# from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client.apps import StarletteOAuth2App
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from fastapi.openapi.docs import get_swagger_ui_html
import os
# from collections.abc import AsyncIterator
# from contextlib import asynccontextmanager
 
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
    
    def get_current_user(request: Request):
        user = request.session.get('user')
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated"
            )
        return user
    
    @app.get('/login')
    async def login(request: Request):

        if "user" in request.session:
            return {"user": request.session['user']}
    
        redirect_uri = request.url_for(f'{PREFIX}auth')
        return await keycloak.authorize_redirect(request, redirect_uri)
    
    @app.get('/auth')
    async def auth(request: Request):
        token = await keycloak.authorize_access_token(request)
        userinfo = dict(token['userinfo'])
        request.session['user'] = userinfo
        return {'token': token, 'user': userinfo}
    
    # TODO: keep ?
    @app.get('/logout')
    async def logout(request: Request):
        request.session.pop('user', None)
        return {'msg': 'Logged out'}
    
    @app.get('/protected')
    async def protected_route(user: dict = Depends(get_current_user )):
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return {'msg': 'You are logged in', 'user': user}
    
    # @router.get("/docs", include_in_schema=False)
    # async def custom_swagger_ui_html(request: Request):
    #     user = request.session.get('user')
    #     if not user:
    #         return RedirectResponse(url='/login')
    #     return get_swagger_ui_html(openapi_url=app.openapi_url, title=app.title + " - Swagger UI")

    return router

async def auth(request: Request) -> AuthInfo:

    token = await keycloak.authorize_access_token(request)
    userinfo = dict(token['userinfo'])
    request.session['user'] = userinfo
    return {'token': token, 'user': userinfo}

