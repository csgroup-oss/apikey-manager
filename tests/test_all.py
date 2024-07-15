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
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.status import (
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_429_TOO_MANY_REQUESTS,
)

from app.auth.apikey_crud import APIKeyCrud
from app.controllers.auth_controller import (
    AuthInfo,
    api_key_header,
    api_key_query,
    oidc_auth,
)
from app.main import get_application
from app.settings import ApiSettings

TESTS_DIR = Path(os.path.realpath(os.path.dirname(__file__)))

#
# Fixture implementations. Note: could be moved to a conftest.py file.
#


@pytest.fixture(scope="session", autouse=True)
def before_and_after():
    """This function is called before and after all the pytests have started/ended."""

    ####################
    # Before all tests #
    ####################

    yield

    ###################
    # After all tests #
    ###################


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


def test_new_apikey(fastapi_app, client):
    """Create a new API key then check its validity."""

    # For each user
    for user_id, iam_roles, config in [
        [USER_ID1, IAM_ROLES1, CONFIG1],
        [USER_ID2, IAM_ROLES2, CONFIG2],
    ]:
        # Mock the AuthInfo instance that contains the user info from keycloak
        fastapi_app.dependency_overrides[oidc_auth] = lambda: AuthInfo(
            user_id, iam_roles
        )

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

        # Check the apikey validity by passing it as http header, url query and url body
        for index, call_endpoint in enumerate(CHECK_APIKEY_ENDPOINTS):

            # Check with the right apikey value
            response = call_endpoint(client, apikey_value)
            response.raise_for_status()
            check_apikey = response.json()
            assert check_apikey == expected_check

            # The "k/{apikey_value}/auth/check_key" endpoint gives 404 with a wrong or missing apikey
            expected_status = HTTP_404_NOT_FOUND if (index == 2) else HTTP_403_FORBIDDEN
            message_404 = "Not Found"

            # Test a wrong apikey value
            response = call_endpoint(client, WRONG_APIKEY)
            assert response.status_code == expected_status
            assert (
                response.json()["detail"] == message_404
                if (index == 2)
                else WRONG_APIKEY_MESSAGE
            )

            # Test a missing apikey. The url body gives a 404.
            response = call_endpoint(client, "")
            assert response.status_code == expected_status
            assert (
                response.json()["detail"] == message_404
                if (index == 2)
                else MISSING_APIKEY_MESSAGE
            )


@pytest.mark.parametrize(
    "call_endpoint",
    CHECK_APIKEY_ENDPOINTS,
    ids=["by http header", "by url query", "by url body"],
)
def test_brute_force(fastapi_app, client, call_endpoint):
    """
    To protect against hacking apikeys by brute force, the user can make only n calls to the
    check endpoint every minute (n is hardcoded in auth_controller.py, see @rate_limiter.limit)
    """
    ncalls = 20

    # Mock the AuthInfo instance that contains the user info from keycloak
    fastapi_app.dependency_overrides[oidc_auth] = lambda: AuthInfo(USER_ID1, IAM_ROLES1)

    # Create a new API key
    response = client.get(
        "/auth/api_key/new", params={"name": "any name", "config": CONFIG1}
    )
    response.raise_for_status()
    apikey_value = response.json()

    # Check that the first n calls to the check endpoint work
    for _ in range(ncalls):
        call_endpoint(client, apikey_value).raise_for_status()

    # The next call fails with error: 429 Too Many Requests
    assert call_endpoint(client, apikey_value).status_code == HTTP_429_TOO_MANY_REQUESTS
