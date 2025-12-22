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

import json
import random
import string
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import BeforeValidator, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from slowapi import Limiter
from slowapi.util import get_remote_address


@dataclass
class AuthInfo:
    user_id: str
    user_login: str
    roles: list[str]
    attributes: dict[str, Any]


def str_to_list(value: Any) -> list:
    """
    Convert into a list a comma-separated str (e.g. 'attr1,attr2') or
    json representation str (e.g. '["attr1", "attr2"]')
    """
    if isinstance(value, str):
        if value.startswith("["):
            return json.loads(value)
        else:
            return [v.strip() for v in value.split(",")]
    else:
        return value


class ApiSettings(BaseSettings):
    """FASTAPI application settings."""

    name: str = "API-Key Manager"
    root_path: str = ""
    debug: bool = False
    cors_origins_regex: str = ".*"  # r".*(geostorm\.eu|csgroup\.space)"
    cors_allow_methods: str = "GET"

    database_url: str = "sqlite:///./test.db"
    default_apikey_ttl_hour: int = 15 * 24  # in hours

    # Admin client id and secret used for oauth2 operations.
    # The client must have have the real_management/view_users
    # and "implicit" flow privileges.
    oidc_endpoint: str = ""
    oidc_realm: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""

    # Random string used to encode cookie-based HTTP sessions in SessionMiddleware
    cookie_secret: str = "".join(
        random.SystemRandom().choice(
            string.ascii_lowercase + string.ascii_uppercase + string.digits
        )
        for _ in range(30)
    )

    # Rate limiter configuration for the check apikey endpoint: after too many requests,
    # the user will receive an error: 429 Too Many Requests
    # This configuration can be e.g. "20/minute" or "100/hour" or "2000/day" ...
    rate_limit: str = "20/minute"

    # Time after which we refresh, in the database,
    # the cached apikey information coming from keycloak.
    # -1 means no sync.
    keycloak_sync_freq: int = 5 * 60  # in seconds

    # Show endpoints in the openapi swagger ?
    show_technical_endpoints: bool = False

    # If False (default): use the OpenIdConnect authentication.
    # If True: use the authlib OAuth authentication instead.
    use_authlib_oauth: bool = False

    # Description displayed in the swagger front page
    swagger_description: str = (
        "APIKeyManager is a centralized Python-oriented API Key manager."
    )

    # Contact name displayed in the swagger front page
    contact_name: str = "CS Group France"

    # Contact url displayed in the swagger front page
    contact_url: str = "https://github.com/csgroup-oss/apikey-manager/"

    # Contact email displayed in the swagger front page
    contact_email: str = "support@csgroup.space"

    # By default, the openapi.json file is under /openapi.json
    # If e.g. Ingress redirects the root domain URL to /docs, it also needs
    # to have the openapi.json file under /docs/openapi.json
    openapi_url: str = "/openapi.json"

    auth_function: Callable | None = None

    # List of optional OAuth2 attributes to save as key/values in the API key "config"
    # dict. The list is given as a comma-separated str (e.g. 'attr1,attr2') or json
    # representation str (e.g. '["attr1", "attr2"]')
    oauth2_attributes: Annotated[
        Sequence[str], BeforeValidator(str_to_list), NoDecode
    ] = []

    model_config = SettingsConfigDict(env_prefix="APIKM_", env_file=".env")

    @field_validator("cors_allow_methods")
    def parse_cors_allow_methods(cls, v):
        """Parse CORS allowed methods."""
        return [method.strip().upper() for method in v.split(",")]

    @field_validator("root_path")
    def parse_root_path(cls, v):
        """Parse root path"""
        return v.rstrip("/")

    @property
    def oidc_metadata_url(self):
        return (
            self.oidc_endpoint
            + "/realms/"
            + self.oidc_realm
            + "/.well-known/openid-configuration"
        )


api_settings = ApiSettings()

rate_limiter = Limiter(key_func=get_remote_address)
