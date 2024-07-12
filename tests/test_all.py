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

import os
from pathlib import Path
from fastapi.testclient import TestClient
import pytest
import tempfile

from starlette.status import HTTP_403_FORBIDDEN


from app.main import get_application
from app.settings import ApiSettings
from app.auth.apikey_crud import APIKeyCrud
from app.controllers.auth_controller import (
    AuthInfo,
    oidc_auth,
    api_key_query,
    api_key_header,
)

TESTS_DIR = Path(os.path.realpath(os.path.dirname(__file__)))

# Temporary sqlite temp file paths
db_paths = []

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

    # Remove sqlite temp files
    for db_path in db_paths:
        os.unlink(db_path)


@pytest.fixture(name="random_db_url")
def random_db_url_(monkeypatch):
    """
    Generate a random sqlite database url for each new pytest
    function so we use a fresh new database for each test.
    """

    # Use the /tests/pytest.db folder
    db_dir = TESTS_DIR / "pytest.db"
    db_dir.mkdir(parents=True, exist_ok=True)

    # Create a temporary file under this dir
    db_path = tempfile.NamedTemporaryFile(
        dir=str(db_dir), suffix=".db", delete=False
    ).name
    db_url = f"sqlite:///{db_path}"

    # Update the env varibale to use this db url
    monkeypatch.setenv("APIKM_DATABASE_URL", db_url)

    # Save the temporary file paths, we'll remove them ourselves at the end of all tests.
    db_paths.append(db_path)


@pytest.fixture(name="fastapi_app")
def fastapi_app_(mocker, random_db_url):
    """Init the FastAPI application."""

    # Patch this global variables with a new APIKeyCrud()
    # so we use the random db url everytime = a fresh new databse.
    # See: https://stackoverflow.com/a/69685866
    mocker.patch("app.auth.apikey_crud.settings", new=ApiSettings(), autospec=False)
    mocker.patch("app.auth.apikey_crud.apikey_crud", new=APIKeyCrud(), autospec=False)

    # Return the FastAPI application
    yield get_application()


@pytest.fixture(name="client")
def client_(fastapi_app):
    """Test the FastAPI application."""
    with TestClient(fastapi_app) as client:
        yield client


#
# Test implementations
#

# Test variables
USER_ID = "user_id"
IAM_ROLES = ["role1", "role2", "role3"]
APIKEY_NAME = "apikey_name"
CONFIG = {}  # TODO test with values, I have error with e.g. {"my": "config"}


async def authinfo():
    """Mock the AuthInfo instance that contains the user info from keycloak"""
    yield AuthInfo(USER_ID, IAM_ROLES)


def test_new_apikey(fastapi_app, client):
    """Create a new API key then check its validity."""

    # Create a new API key
    fastapi_app.dependency_overrides[oidc_auth] = authinfo
    response = client.get(
        "/auth/api_key/new", params={"name": APIKEY_NAME, "config": CONFIG}
    )
    response.raise_for_status()
    apikey_value = response.json()

    # Expected result when we check its validity
    expected = {"user_id": USER_ID, "iam_roles": IAM_ROLES, "config": CONFIG}

    # Check its validity when passing the apikey as http header
    response = client.get(
        "/auth/check_key", headers={api_key_header.model.name: apikey_value}
    )
    response.raise_for_status()
    check_apikey = response.json()
    assert check_apikey == expected

    # We should have be unauthorized without the apikey (no cache)
    response = client.get("/auth/check_key")
    assert response.status_code == HTTP_403_FORBIDDEN

    # Check its validity when passing the apikey in the url query
    response = client.get(
        "/auth/check_key", params={api_key_query.model.name: apikey_value}
    )
    response.raise_for_status()
    check_apikey = response.json()
    assert check_apikey == expected

    # Check again that we are unauthorized without the apikey (no cache)
    response = client.get("/auth/check_key")
    assert response.status_code == HTTP_403_FORBIDDEN

    # Check its validity when passing it in the url
    response = client.get(f"k/{apikey_value}/auth/check_key")
    response.raise_for_status()
    check_apikey = response.json()
    assert check_apikey == expected

    # Check again that we are unauthorized without the apikey (no cache)
    response = client.get("/auth/check_key")
    assert response.status_code == HTTP_403_FORBIDDEN
