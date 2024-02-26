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


# Add a rate limiter to avoid cracking the api keys by brute force.
# See: https://slowapi.readthedocs.io/en/latest/#fastapi
rate_limiter = Limiter(key_func=get_remote_address)
