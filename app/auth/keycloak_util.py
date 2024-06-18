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


import logging
from dataclasses import dataclass

from keycloak import KeycloakAdmin, KeycloakError, KeycloakOpenIDConnection
from keycloak.exceptions import KeycloakGetError

from .. import settings

LOGGER = logging.getLogger(__name__)


@dataclass
class KCInfo:
    is_enabled: bool
    roles: list[str] | None


class KCUtil:
    def __init__(self) -> None:
        self.keycloak_admin = self.__get_keycloak_admin()

    def __get_keycloak_admin(self) -> KeycloakAdmin:
        """Init and return an admin keycloak connection from the admin client"""
        LOGGER.debug(
            f"Connecting to the keycloak server {settings.OAUTH2_SERVER_URL} ..."
        )
        try:
            keycloak_connection = KeycloakOpenIDConnection(
                server_url=settings.OAUTH2_SERVER_URL,
                realm_name=settings.OAUTH2_REALM,
                client_id=settings.OAUTH2_CLIENT_ID,
                client_secret_key=str(settings.OAUTH2_CLIENT_SECRET),
                verify=True,
            )
            LOGGER.debug("Connected to the keycloak server")
            return KeycloakAdmin(connection=keycloak_connection)

        except KeycloakError as error:
            raise RuntimeError(
                f"Error connecting with keycloak to '{settings.OAUTH2_SERVER_URL}', "
                f"realm_name={settings.OAUTH2_REALM} with client_id="
                f"{settings.OAUTH2_CLIENT_ID}."
            ) from error

    def get_user_info(self, user_id: str) -> KCInfo:
        """Get user info from keycloak"""
        try:
            kadm = self.keycloak_admin
            user = kadm.get_user(user_id)
            iam_roles = [
                role["name"] for role in kadm.get_composite_realm_roles_of_user(user_id)
            ]
            return KCInfo(user["enabled"], iam_roles)
        except KeycloakGetError as error:
            # If the user is not found, this means he was removed from keycloak.
            # Thus we must remove all his api keys from the database.
            if (error.response_code == 404) and (
                "User not found" in error.response_body.decode("utf-8")
            ):
                LOGGER.warning(f"User '{user_id}' not found in keycloak.")
                return KCInfo(False, None)

            raise
