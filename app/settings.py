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

from collections.abc import Callable

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter
from slowapi.util import get_remote_address


class ApiSettings(BaseSettings):
    """FASTAPI application settings."""

    name: str = "API-Key Manager"
    root_path: str = ""
    debug: bool = False
    cors_origins_regex: str = ".*"  # r".*(geostorm\.eu|csgroup\.space)"
    cors_allow_methods: str = "GET"

    database_url: str = "sqlite:///./test.db"
    default_apikey_ttl_hour: int = 15 * 24  # in hour

    oidc_endpoint: str = ""
    oidc_realm: str = ""
    oidc_client_id: str = ""

    # Admin client id and secret used for oauth2 operations.
    # The client must have have the real_management/view_users
    # and "implicit" flow privileges.
    #  -1 means no sync
    keycloak_sync_freq: int = 5 * 60
    oidc_client_secret: str = ""

    # Show endpoints in the openapi swagger ?
    show_technical_endpoints: bool = False

    auth_function: Callable | None = None

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
