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


"""Interaction with database.
"""
import hashlib
import logging
import threading
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    Row,
    String,
    Table,
    create_engine,
    desc,
    select,
)
from starlette.status import HTTP_404_NOT_FOUND, HTTP_422_UNPROCESSABLE_ENTITY

from ..settings import api_settings as settings
from .keycloak_util import KCUtil

LOGGER = logging.getLogger(__name__)

LIST_API_KEYS = True


class APIKeyCrud:
    """Class handling SQLite connection and writes"""

    def __init__(self) -> None:
        self.engine = create_engine(
            settings.database_url, echo=settings.debug, pool_pre_ping=True
        )

        meta = MetaData()

        self.t_apitoken = Table(
            "api_tokens",
            meta,
            Column("api_key", String, primary_key=True, index=True),
            Column("name", String),
            # User ID in keycloak
            Column("user_id", String, index=True, nullable=False),
            Column("user_login", String),
            # Is the user active in keycloak ? True by defulat, because
            # to create an apikey, the user must be authenticated to keycloak.
            Column("user_active", Boolean, default=True),
            # Is the apikey active = not revoked manually ?
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

        self.kcutil = KCUtil()

    def __hash(self, api_key):
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

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
                    api_key=self.__hash(api_key),
                    name=name,
                    user_id=user_id,
                    user_login=user_login,
                    never_expire=never_expire,
                    expiration_date=datetime.now(UTC)
                    + timedelta(hours=settings.default_apikey_ttl_hour),
                    latest_sync_date=datetime.now(UTC),
                    iam_roles=iam_roles,
                    config=config,
                    allowed_referers=allowed_referers,
                )
            )
            conn.commit()

        return api_key

    def renew_key(
        self, user_id: str, api_key: str, new_expiration_date: str | None
    ) -> str | None:
        with self.engine.connect() as conn:
            t = self.t_apitoken
            resp = conn.execute(
                select(t.c["is_active", "expiration_date"]).where(
                    (t.c.api_key == self.__hash(api_key)) & (t.c.user_id == user_id)
                )
            ).first()

            # API key not found
            if not resp:
                raise HTTPException(
                    status_code=HTTP_404_NOT_FOUND, detail="API key not found"
                )

            response_lines = []

            # Previously revoked key. Issue a text warning and reactivate it.
            if not resp[0]:
                response_lines.append(
                    "This API key was revoked and has been reactivated."
                )

            # Without an expiration date, we set it here
            if not new_expiration_date:
                parsed_expiration_date = datetime.now(UTC) + timedelta(
                    hours=settings.default_apikey_ttl_hour
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
                .where(t.c.api_key == self.__hash(api_key))
                .values(
                    latest_sync_date=datetime.now(UTC),
                    is_active=True,
                    expiration_date=parsed_expiration_date,
                )
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

        with self.engine.connect() as conn:
            t = self.t_apitoken
            conn.execute(
                t.update()
                .where((t.c.api_key == self.__hash(api_key)) & (t.c.user_id == user_id))
                .values(latest_sync_date=datetime.now(UTC), is_active=False)
            )

            conn.commit()

    def check_key(self, api_key: str) -> dict | None:
        """
        Checks if an API key is valid

        Args:
             api_key: the API key to validate
        """

        with self.engine.connect() as conn:
            t = self.t_apitoken
            row = conn.execute(
                select(
                    t.c[
                        "user_id",
                        "user_login",
                        "user_active",
                        "is_active",
                        "iam_roles",
                        "config",
                        "latest_sync_date",
                    ]
                ).where(
                    (t.c.api_key == self.__hash(api_key))
                    & (t.c.never_expire | (t.c.expiration_date > datetime.now(UTC)))
                )
            ).first()

            if not row:
                # If the apikey is expired, directly return None
                return None

            response = row._asdict()

            # If the apikey has been revoked manually, then it can
            # only be renewed manually.
            if not response["is_active"]:
                return None

            latest_sync_date = response["latest_sync_date"]
            # SQLite does not store timezone. Small warkaround
            if latest_sync_date.utcoffset() is None:
                latest_sync_date = latest_sync_date.replace(tzinfo=timezone.utc)

            if settings.keycloak_sync_freq > 0 and datetime.now(UTC) > (
                latest_sync_date + timedelta(seconds=settings.keycloak_sync_freq)
            ):
                LOGGER.debug(f"Sync user info of `{response['user_id']}` with KeyCLoak")
                kc_info = self.kcutil.get_user_info(response["user_id"])
                # Update the database
                conn.execute(
                    t.update()
                    .where(t.c.api_key == self.__hash(api_key))
                    .values(
                        user_active=kc_info.is_enabled,
                        iam_roles=kc_info.roles,
                        latest_sync_date=datetime.now(UTC),
                    )
                )
                conn.commit()

                response["user_active"] = kc_info.is_enabled
                response["iam_roles"] = kc_info.roles

            if not response["user_active"]:
                # If user is not active anymore
                return None

            # We run the logging in a separate thread as writing takes some time
            threading.Thread(
                target=self._update_usage,
                args=(api_key,),
            ).start()

            # We return directly
            return response

    def _update_usage(self, api_key: str) -> None:
        with self.engine.connect() as conn:
            t = self.t_apitoken
            conn.execute(
                t.update()
                .where(t.c.api_key == self.__hash(api_key))
                .values(
                    total_queries=t.c.total_queries + 1,
                    latest_query_date=datetime.now(UTC),
                )
            )
            conn.commit()

    def get_usage_stats(self, user_id: str) -> Sequence[Row[Any]]:
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
