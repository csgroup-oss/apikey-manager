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

import hashlib
import os
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.status import (
    HTTP_200_OK,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_429_TOO_MANY_REQUESTS,
)

from app.auth import apikey_crud
from app.auth.apikey_crud import APIKeyCrud
from app.auth.keycloak_util import KCInfo
from app.controllers.auth_controller import (
    AuthInfo,
    api_key_header,
    api_key_query,
    oidc_auth,
    rate_limiter,
)
from app.main import get_application
from app.settings import ApiSettings

TESTS_DIR = Path(os.path.realpath(os.path.dirname(__file__)))

#
# Fixture implementations. Note: could be moved to a conftest.py file.
#


@pytest.fixture
def random_db_url(monkeypatch):
    """
    Generate a random sqlite database url for each new pytest
    function so we use a fresh new database for each test.
    """

    # Use the /tests/pytest.db folder
    db_dir = TESTS_DIR / "pytest.db"
    db_dir.mkdir(parents=True, exist_ok=True)

    # Create a temporary file under this dir
    with tempfile.NamedTemporaryFile(dir=str(db_dir), suffix=".db") as db_path:
        db_url = f"sqlite:///{db_path.name}"

        # Update the env varibale to use this db url
        monkeypatch.setenv("APIKM_DATABASE_URL", db_url)

        # The temp file will be removed at the end of the test
        yield


@pytest.fixture
def fastapi_app(mocker, random_db_url):
    """Init the FastAPI application."""

    # Read the mocked environment variables in a new ApiSettings object
    # See: https://stackoverflow.com/a/69685866
    settings = ApiSettings()
    mocker.patch("app.auth.apikey_crud.settings", new=settings, autospec=False)
    mocker.patch("app.auth.keycloak_util.settings", new=settings, autospec=False)
    mocker.patch(
        "app.controllers.auth_controller.api_settings", new=settings, autospec=False
    )
    mocker.patch("app.main.api_settings", new=settings, autospec=False)
    mocker.patch("app.settings.api_settings", new=settings, autospec=False)

    # Patch this global variables with a new APIKeyCrud()
    # so we use the random db url everytime = a fresh new databse.
    apikey_crud = APIKeyCrud()
    mocker.patch("app.auth.apikey_crud.apikey_crud", new=apikey_crud, autospec=False)
    mocker.patch(
        "app.controllers.auth_controller.apikey_crud", new=apikey_crud, autospec=False
    )

    # Return the FastAPI application
    yield get_application()


@pytest.fixture
def client(fastapi_app):
    """Test the FastAPI application."""
    with TestClient(fastapi_app) as client:
        yield client


@pytest.fixture(autouse=True)
def reset_rate_limiter(mocker, fastapi_app):
    """
    Reset the rate limiter before each test.
    NOTE: maybe we need to mock this somehow for this test only so it doesn't impact other tests.
    """
    rate_limiter.reset()


def mock_keycloak_info(
    mocker,
    fastapi_app,
    user_id: str,
    iam_roles: list[str],
    enabled_in_keycloak: bool = True,
):
    """Mock the user info returned from keycloak."""

    # Mock the AuthInfo instance returned by OpenIdConnect
    fastapi_app.dependency_overrides[oidc_auth] = lambda: AuthInfo(user_id, iam_roles)

    # Mock the KCInfo instance returned by keycloak.KeycloakAdmin
    mocker.patch(
        "app.auth.keycloak_util.KCUtil.get_user_info",
        return_value=KCInfo(enabled_in_keycloak, iam_roles),
    )


#
# Test implementations
#

# Test variables

USER_ID1 = "user_id1"
IAM_ROLES1 = ["role1", "role2", "role3"]
CONFIG1 = {}  # TODO test with values, I have error with e.g. {"my": "config"}

USER_ID2 = "user_id2"
IAM_ROLES2 = ["role4", "role5"]
CONFIG2 = {}  # TODO test with values

WRONG_APIKEY = "wrong_apikey"
WRONG_APIKEY_MESSAGE = "Wrong, revoked, or expired API key."
MISSING_APIKEY_MESSAGE = "An API key must be passed as query or header"
MESSAGE_404 = "Not Found"

# Check the apikey validity by passing it as http header, url query and url body
CHECK_APIKEY_ENDPOINTS = [
    lambda client, apikey_value: client.get(
        "/auth/check_key", headers={api_key_header.model.name: apikey_value}
    ),
    lambda client, apikey_value: client.get(
        "/auth/check_key", params={api_key_query.model.name: apikey_value}
    ),
    lambda client, apikey_value: client.get(f"k/{apikey_value}/auth/check_key"),
]
CHECK_APIKEY_IDS = ["by_http_header", "by_url_query", "by_url_body"]


@pytest.mark.parametrize(
    "check_endpoint, wrong_status, wrong_message, missing_message",
    [
        [
            CHECK_APIKEY_ENDPOINTS[0],
            HTTP_403_FORBIDDEN,
            WRONG_APIKEY_MESSAGE,
            MISSING_APIKEY_MESSAGE,
        ],
        [
            CHECK_APIKEY_ENDPOINTS[1],
            HTTP_403_FORBIDDEN,
            WRONG_APIKEY_MESSAGE,
            MISSING_APIKEY_MESSAGE,
        ],
        [CHECK_APIKEY_ENDPOINTS[2], HTTP_404_NOT_FOUND, MESSAGE_404, MESSAGE_404],
    ],
    ids=CHECK_APIKEY_IDS,
)
def test_new_apikey(
    mocker,
    fastapi_app,
    client,
    check_endpoint,
    wrong_status,
    wrong_message,
    missing_message,
):
    """Create a new API key then check its validity."""

    # For each user
    for user_id, iam_roles, config in [
        [USER_ID1, IAM_ROLES1, CONFIG1],
        [USER_ID2, IAM_ROLES2, CONFIG2],
    ]:
        # Mock the user info returned from keycloak
        mock_keycloak_info(mocker, fastapi_app, user_id, iam_roles)

        # Create a new API key
        response = client.get(
            "/auth/api_key/new", params={"name": "any name", "config": config}
        )
        response.raise_for_status()
        apikey_value = response.json()

        # List the apikeys for the current user.
        # We should have a single apikey for each user.
        response = client.get("/auth/api_key/list")
        response.raise_for_status()
        usage_logs = response.json()
        assert len(usage_logs) == 1

        # Check its hashed value
        assert (
            hashlib.sha256(apikey_value.encode("utf-8")).hexdigest()
            == usage_logs[0]["api_key"]
        )

        # Expected result of the check/api_key endpoint
        expected_check = {"user_id": user_id, "iam_roles": iam_roles, "config": config}

        # Check the apikey validity by passing it as http header, url query or url body.
        # Check with the right apikey value.
        response = check_endpoint(client, apikey_value)
        response.raise_for_status()
        check_apikey = response.json()
        assert check_apikey == expected_check

        # Test a wrong apikey value.
        # By http header or url query, we should have a 403.
        # By url body, we should have a 404.
        response = check_endpoint(client, WRONG_APIKEY)
        assert response.status_code == wrong_status
        assert response.json()["detail"] == wrong_message

        # Test a missing apikey.
        response = check_endpoint(client, "")
        assert response.status_code == wrong_status
        assert response.json()["detail"] == missing_message


@pytest.mark.parametrize(
    "check_endpoint",
    CHECK_APIKEY_ENDPOINTS,
    ids=CHECK_APIKEY_IDS,
)
def test_brute_force(mocker, fastapi_app, client, check_endpoint):
    """
    To protect against hacking apikeys by brute force, the user can make only n calls to the
    check endpoint (n is set in configuration by the APIKM_RATE_LIMIT env var)
    """
    ncalls = 20

    # Mock the user info returned from keycloak
    mock_keycloak_info(mocker, fastapi_app, USER_ID1, IAM_ROLES1)

    # Create a new API key
    response = client.get(
        "/auth/api_key/new", params={"name": "any name", "config": CONFIG1}
    )
    response.raise_for_status()
    apikey_value = response.json()

    # Check that the first n calls to the check endpoint work
    for _ in range(ncalls):
        check_endpoint(client, apikey_value).raise_for_status()

    # The next call fails with error: 429 Too Many Requests
    assert (
        check_endpoint(client, apikey_value).status_code == HTTP_429_TOO_MANY_REQUESTS
    )


@pytest.mark.parametrize(
    "check_endpoint",
    CHECK_APIKEY_ENDPOINTS,
    ids=CHECK_APIKEY_IDS,
)
def test_cache(mocker, fastapi_app, client, check_endpoint):
    """
    When calling the check apikey endpoint, the response is saved in cache for some time.
    But we won't have the right values if the user rights have changed in keycloak in the meantime.
    """

    # Modify the refresh time in seconds to call keycloak again
    apikey_crud.settings.keycloak_sync_freq = 0.5
    time_to_sleep = 0.51

    # Mock the user info returned from keycloak
    mock_keycloak_info(mocker, fastapi_app, USER_ID1, IAM_ROLES1)

    # Create a new API key
    response = client.get(
        "/auth/api_key/new", params={"name": "any name", "config": CONFIG1}
    )
    response.raise_for_status()
    apikey_value = response.json()

    # Call the check apikey endpoint: the returned roles for the apikey should be
    # the same as the user roles in keycloak
    response = check_endpoint(client, apikey_value)
    response.raise_for_status()
    assert response.json()["iam_roles"] == IAM_ROLES1

    # Mock the user info returned from keycloak
    mock_keycloak_info(mocker, fastapi_app, USER_ID1, IAM_ROLES2)

    # If we call the check api endpoint again, we don't see the change immediately
    response = check_endpoint(client, apikey_value)
    response.raise_for_status()
    assert response.json()["iam_roles"] == IAM_ROLES1

    # But after some time, the endpoint refreshes the user info from keycloak and we can see the change
    time.sleep(time_to_sleep)
    response = check_endpoint(client, apikey_value)
    response.raise_for_status()
    assert response.json()["iam_roles"] == IAM_ROLES2


# We want to check what happens when a user is disabled/enabled in keycloak,
# when an apikey is revoked/renewed or is expired.
# What happens when we switch from one state to another ? Test all cases.
all_states = [
    ["user_NO-revoked_NO-expired_NO", [False, False, False]],
    ["user_NO-revoked_NO-expired_YES", [False, False, True]],
    ["user_NO-revoked_YES-expired_NO", [False, True, False]],
    ["user_NO-revoked_YES-expired_YES", [False, True, True]],
    ["user_YES-revoked_NO-expired_NO", [True, False, False]],
    ["user_YES-revoked_NO-expired_YES", [True, False, True]],
    ["user_YES-revoked_YES-expired_NO", [True, True, False]],
    ["user_YES-revoked_YES-expired_YES", [True, True, True]],
]
state_changes = []
state_ids = []
for from_state in all_states:
    for to_state in all_states:
        state_changes.append(from_state[1] + to_state[1])
        state_ids.append(f"{from_state[0]}__to__{to_state[0]}")


@pytest.mark.parametrize(
    "from_user_ok, from_revoked, from_expired, to_user_ok, to_revoked, to_expired",
    state_changes,
    ids=state_ids,
)
def test_state_changes(
    mocker,
    fastapi_app,
    client,
    from_user_ok,
    from_revoked,
    from_expired,
    to_user_ok,
    to_revoked,
    to_expired,
):
    """Switch from a disabled/enabled user in keycloak and a revoked/renewed apikey, to another state"""

    # Print the apikey usage info
    def debug_apikey():
        import json

        response = client.get("/auth/api_key/list")
        response.raise_for_status()
        usage_logs = response.json()
        assert len(usage_logs) == 1
        print(json.dumps(usage_logs[0], indent=2))

    # Test only using the apikey passed by http header, it should be enough
    check_endpoint = CHECK_APIKEY_ENDPOINTS[0]

    # Modify the refresh time in seconds to call keycloak again
    apikey_crud.settings.keycloak_sync_freq = 0.01
    time_to_sleep = 0.02

    # Mock the user info returned from keycloak, at first he's always enabled
    mock_keycloak_info(mocker, fastapi_app, USER_ID1, IAM_ROLES1, True)

    # Create a new API key
    response = client.get(
        "/auth/api_key/new", params={"name": "any name", "config": CONFIG1}
    )
    response.raise_for_status()
    apikey_value = response.json()

    # At first the user is enabled, the apikey is not revoked and not expired
    old_user_ok = True
    old_revoked = False
    old_expired = False

    # Go to first then second state
    for user_ok, revoked, expired in [
        [from_user_ok, from_revoked, from_expired],
        [to_user_ok, to_revoked, to_expired],
    ]:
        # Do we switch states ?
        switch_user_ok = user_ok != old_user_ok
        switch_revoked = revoked != old_revoked
        switch_expired = expired != old_expired
        old_user_ok = user_ok
        old_revoked = revoked
        old_expired = expired

        # Mock the user info returned from keycloak to enabled/disable the user
        if switch_user_ok:
            mock_keycloak_info(mocker, fastapi_app, USER_ID1, IAM_ROLES1, user_ok)

        # If we switch the revoke or expired status: update the database
        if switch_revoked or switch_expired:
            values = {}
            if switch_revoked:
                values["is_active"] = not revoked
            if switch_expired:
                future = -1 if expired else 1  # -1 for past, 1 for future
                values["expiration_date"] = datetime.now(UTC) + timedelta(
                    hours=future * apikey_crud.settings.default_apikey_ttl_hour
                )

            # Use the apikey_crud instance to update the database
            crud = apikey_crud.apikey_crud
            with crud.engine.connect() as conn:
                t = crud.t_apitoken
                conn.execute(
                    t.update()
                    .where(
                        t.c.api_key == crud._APIKeyCrud__hash(apikey_value)
                    )  # call private method
                    .values(**values)
                )
                conn.commit()

        # To refresh from keycloak
        time.sleep(time_to_sleep)

        # Call the check apikey endpoint.
        # We should have a nominal response only if the user is enabled in keycloak,
        # the apikey is active and non-expired.
        debug_apikey()
        response = check_endpoint(client, apikey_value)
        debug_apikey()
        if user_ok and (not revoked) and (not expired):
            assert response.status_code == HTTP_200_OK
            assert response.json()["iam_roles"] == IAM_ROLES1
        else:
            assert response.status_code == HTTP_403_FORBIDDEN
