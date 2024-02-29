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

from os import environ as env

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter
from slowapi.util import get_remote_address


class ApiSettings(BaseSettings):
    """FASTAPI application settings."""

    name: str = "API-Key Manager"
    cors_origins_regex: str = ".*"  # r".*(geostorm\.eu|csgroup\.space)"
    cors_allow_methods: str = "GET"
    cachecontrol: str = "public, max-age=3600"
    root_path: str = ""
    debug: bool = True

    disable_cog: bool = False
    disable_stac: bool = False
    disable_mosaic: bool = False

    lower_case_query_parameters: bool = False

    model_config = SettingsConfigDict(env_prefix="GEOJSONPROXY_", env_file=".env")

    @field_validator("cors_allow_methods")
    def parse_cors_allow_methods(cls, v):
        """Parse CORS allowed methods."""
        return [method.strip().upper() for method in v.split(",")]

    @field_validator("root_path")
    def parse_root_path(cls, v):
        """Parse root path"""
        return v.rstrip("/")


##################
# Other settings #
##################

# Add a rate limiter to avoid cracking the api keys by brute force.
# See: https://slowapi.readthedocs.io/en/latest/#fastapi
rate_limiter = Limiter(key_func=get_remote_address)

#########################
# Environment variables #
#########################


def env_bool(var: str, default: bool) -> bool:
    """
    Return True if an environemnt variable is set to 1, true or yes (case insensitive).
    Return False if set to 0, false or no (case insensitive).
    Return the default value if not set or set to a different value.
    """
    try:
        env_var = env[var].lower()  # read the env var value
    except KeyError:
        return default  # env var is not set

    if (env_var == "1") or (env_var == "true") or (env_var == "yes"):
        return True
    elif (env_var == "0") or (env_var == "false") or (env_var == "no"):
        return False
    return default


# See https://github.com/marcospereirampj/python-keycloak/issues/89
# There has been a change to KeyCloak recently, and it doesn't map the client ID
# into the auth field of the token by default any more.
# Disable this audience check as a workaround.
# TODO: do we want to keep this ?
VERIFY_AUDIENCE = env_bool("VERIFY_AUDIENCE", default=True)

# Show endpoints in the openapi swagger ?
SHOW_APIKEY_ENDPOINTS = env_bool("SHOW_APIKEY_ENDPOINTS", default=True)
SHOW_TECHNICAL_ENDPOINTS = env_bool("SHOW_TECHNICAL_ENDPOINTS", default=True)

# Local administrator account to update apikey info in database from oauth2
LOCAL_ADMIN_USER = env.get("LOCAL_ADMIN_USER", None)
LOCAL_ADMIN_PASSWORD = env.get("LOCAL_ADMIN_PASSWORD", None)
