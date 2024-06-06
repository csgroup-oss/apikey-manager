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


"""Interaction with database.
"""
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta

from fastapi import HTTPException
from keycloak import KeycloakAdmin, KeycloakError, KeycloakOpenIDConnection
from keycloak.exceptions import KeycloakConnectionError, KeycloakGetError
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    desc,
    select,
)
from starlette.status import (
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_422_UNPROCESSABLE_ENTITY,
)

from ..settings import (
    OAUTH2_CLIENT_ID,
    OAUTH2_CLIENT_SECRET,
    OAUTH2_REALM,
    OAUTH2_SERVER_URL,
)

LIST_API_KEYS = True

# NOTE : use from databases import Database for working with async pg
# https://fastapi.tiangolo.com/how-to/async-sql-encode-databases/#import-and-set-up-databases

DATABASE_URL = os.environ.get("API_KEYS_DB_URL", "sqlite:///./test.db")

# TODO: add to helm charts ?
EXPIRATION_LIMIT = int(os.environ.get("API_KEYS_EXPIRE_IN_DAYS", "15"))

# Limit in minutes after which we should update the API key information
# in the database from the keycloak user information
# TODO: add to helm charts ?
SYNC_LIMIT = timedelta(minutes=float(os.environ.get("API_KEYS_SYNC_IN_MINUTES", "5")))

LOGGER = logging.getLogger(__name__)

DEBUG = bool(os.environ.get("DEBUG", False))


class APIKeyCrud:
    """Class handling SQLite connection and writes"""

    def __init__(self) -> None:
        self.engine = create_engine(DATABASE_URL, echo=DEBUG, pool_pre_ping=True)

        meta = MetaData()

        self.t_apitoken = Table(
            "api_tokens",
            meta,
            Column("api_key", String, primary_key=True, index=True),
            Column("name", String),
            Column("user_id", String, index=True, nullable=False),
            Column("user_login", String),
            Column("is_active", Boolean, default=True),
            Column("never_expire", Boolean, default=False),
            Column("expiration_date", DateTime),
            Column("latest_query_date", DateTime),
            Column("total_queries", Integer, default=0),
            Column("latest_sync_date", DateTime),
            Column("iam_roles", JSON, default=[]),
            Column("config", JSON, default={}),
            Column("allowed_referers", JSON, default=None),
        )

        meta.create_all(self.engine)

        self.keycloak_admin: KeycloakAdmin = None

    def get_keycloak_admin(self):
        """Init and return an admin keycloak connection from the admin client"""

        # TODO: add a thread lock to be sure to execute only once ?

        if self.keycloak_admin:
            return self.keycloak_admin

        print(  # TODO use logger # noqa: T201
            f"Connecting to the keycloak server {OAUTH2_SERVER_URL!r} ..."
        )

        try:
            keycloak_connection = KeycloakOpenIDConnection(
                server_url=OAUTH2_SERVER_URL,
                realm_name=OAUTH2_REALM,
                client_id=OAUTH2_CLIENT_ID,
                client_secret_key=str(OAUTH2_CLIENT_SECRET),
                verify=True,
            )
            self.keycloak_admin = KeycloakAdmin(connection=keycloak_connection)
            print("Connected to the keycloak server")  # TODO use logger # noqa: T201
            return self.keycloak_admin

        except KeycloakError as error:
            raise RuntimeError(
                f"Error connecting with keycloak to server_url={OAUTH2_SERVER_URL!r}, "
                f"realm_name={OAUTH2_REALM!r} with client_id={OAUTH2_CLIENT_ID!r}"
            ) from error

    def create_key(
        self,
        name: str,
        user_id: str,
        user_login: str,
        never_expire: bool,
        iam_roles: list[str],
        config: dict,
        allowed_referers: list[str] | None,
    ) -> str:
        api_key = str(uuid.uuid4())
        with self.engine.connect() as conn:
            conn.execute(
                self.t_apitoken.insert().values(
                    api_key=api_key,
                    name=name,
                    user_id=user_id,
                    user_login=user_login,
                    never_expire=never_expire,
                    expiration_date=datetime.utcnow()
                    + timedelta(days=EXPIRATION_LIMIT),
                    latest_sync_date=datetime.utcnow(),
                    iam_roles=iam_roles,
                    config=config,
                    allowed_referers=allowed_referers,
                )
            )
            conn.commit()

        return api_key

    def check_key_user(self, user_id: str, api_key: str) -> None:
        """
        Check that an api key exists and belongs to a user.

        Raises:
            404 HTTP exception if the key doesn't exist.
            403 HTTP exception if the key doesn't belong to the user.
        """
        with self.engine.connect() as conn:
            t = self.t_apitoken
            resp = conn.execute(
                select(t.c["user_id"]).where(t.c.api_key == api_key)
            ).first()

            # API key not found
            if not resp:
                raise HTTPException(
                    status_code=HTTP_404_NOT_FOUND, detail="API key not found"
                )

            if resp[0] != user_id:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="You are not the owner of this API key",
                )

    def renew_key(
        self, user_id: str, api_key: str, new_expiration_date: str | None
    ) -> str | None:
        # Check that the api key exists and belongs to the given user.
        self.check_key_user(user_id, api_key)

        with self.engine.connect() as conn:
            t = self.t_apitoken
            resp = conn.execute(
                select(
                    t.c["is_active", "total_queries", "expiration_date", "never_expire"]
                ).where(t.c.api_key == api_key)
            ).first()

            response_lines = []

            # Previously revoked key. Issue a text warning and reactivate it.
            if not resp[0]:
                response_lines.append(
                    "This API key was revoked and has been reactivated."
                )

            # Without an expiration date, we set it here
            if not new_expiration_date:
                parsed_expiration_date = datetime.utcnow() + timedelta(
                    days=EXPIRATION_LIMIT
                )

            else:
                try:
                    # We parse and re-write to the right timespec
                    parsed_expiration_date = datetime.fromisoformat(new_expiration_date)
                except ValueError as exc:
                    raise HTTPException(
                        status_code=HTTP_422_UNPROCESSABLE_ENTITY,
                        detail="The expiration date could not be parsed. \
                            Please use ISO 8601.",
                    ) from exc

            conn.execute(
                t.update()
                .where(t.c.api_key == api_key)
                .values(is_active=True, expiration_date=parsed_expiration_date)
            )

            conn.commit()

            response_lines.append(
                f"The new expiration date for the API key is {parsed_expiration_date}"
            )

            return " ".join(response_lines)

    def revoke_key(self, user_id: str, api_key: str) -> None:
        """
        Revokes an API key

        Args:
            api_key: the API key to revoke
        """

        # Check that the api key exists and belongs to the given user.
        self.check_key_user(user_id, api_key)

        with self.engine.connect() as conn:
            t = self.t_apitoken
            conn.execute(
                t.update().where(t.c.api_key == api_key).values(is_active=False)
            )

            conn.commit()

    def __update_key_from_keycloak(self, api_key: str) -> None:
        """
        From time to time we update the API key information in the database
        from the keycloak user information
        """

        # For now disable this,
        # see: https://pforge-exchange2.astrium.eads.net/jira/browse/RSPY-292
        return

        with self.engine.connect() as conn:
            t = self.t_apitoken

            # Get the owner (user id) of the api key from database
            response = conn.execute(
                select(t.c["user_id", "user_login", "latest_sync_date"]).where(
                    t.c.api_key == api_key
                )
            ).first()

            # The api key doesn't exist or if the last sync is too recent, do nothing
            if (not response) or ((datetime.utcnow() - response[2]) < SYNC_LIMIT):
                return None

            user_id = response[0]
            user_login = response[1]

            # Get user info from keycloak
            try:
                user = self.get_keycloak_admin().get_user(user_id)
                is_active = user["enabled"]
                iam_roles = [
                    role["name"]
                    for role in self.keycloak_admin.get_realm_roles_of_user(user_id)
                ]

            except KeycloakGetError as error:
                # If the user is not found, this means he was removed from keycloak.
                # Thus we must remove all his api keys from the database.
                if (error.response_code == 404) and (
                    "User not found" in error.response_body.decode("utf-8")
                ):
                    LOGGER.warning(
                        f"User '{user_login}/{user_id}' not found in keycloak. "
                        "We remove their api keys from the database."
                    )
                    conn.execute(t.delete().where(t.c.user_id == user_id))
                    conn.commit()
                    return

                # Else just raise other errors.
                # TODO: what could they be ? Handle special cases ?
                raise

            # Connection error to the keycloak (e.g. service unavailable):
            # log error and do nothing more (don't update database)
            # TODO: to be confirmed.
            except KeycloakConnectionError as error:
                LOGGER.error(error)
                return

            # Raise any other error.
            # TODO: what could they be ? Handle special cases ?
            # except Exception:
            #     raise

            # Update the database
            conn.execute(
                t.update()
                .where(t.c.api_key == api_key)
                .values(
                    is_active=is_active,
                    iam_roles=iam_roles,
                    latest_sync_date=datetime.utcnow(),
                )
            )
            conn.commit()

    def check_key(self, api_key: str) -> dict | None:
        """
        Checks if an API key is valid

        Args:
             api_key: the API key to validate
        """

        self.__update_key_from_keycloak(api_key)

        with self.engine.connect() as conn:
            t = self.t_apitoken
            response = conn.execute(
                select(t.c["user_login", "iam_roles", "config"]).where(
                    (t.c.api_key == api_key)
                    & t.c.is_active
                    & (t.c.never_expire | (t.c.expiration_date > datetime.utcnow()))
                )
            ).first()

            if not response:
                return None
            else:
                # The key is valid

                # We run the logging in a separate thread as writing takes some time
                threading.Thread(
                    target=self._update_usage,
                    args=(api_key,),
                ).start()

                # We return directly
                return response._asdict()

    def _update_usage(self, api_key: str) -> None:
        with self.engine.connect() as conn:
            t = self.t_apitoken
            conn.execute(
                t.update()
                .where(t.c.api_key == api_key)
                .values(
                    total_queries=t.c.total_queries + 1,
                    latest_query_date=datetime.utcnow(),
                )
            )
            conn.commit()

    def get_usage_stats(
        self, user_id: str
    ) -> list[
        tuple[
            str,
            str,
            str,
            str,
            bool,
            bool,
            datetime,
            datetime,
            int,
            datetime,
            dict,
            dict,
            dict,
        ]
    ]:
        """
        Returns usage stats for all API keys

        Returns:
            a list of tuples with values being api_key, is_active, expiration_date, \
                latest_query_date, and total_queries
        """

        with self.engine.connect() as conn:
            t = self.t_apitoken
            res = conn.execute(
                select(t)
                .where(t.c.user_id == user_id)
                .order_by(desc(t.c.latest_query_date))
            ).all()

        return res


apikey_crud = APIKeyCrud()
