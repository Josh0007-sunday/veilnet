"""
Example test file for demonstrating how to test a new feature.
"""
import pytest
from fastapi.testclient import TestClient
import os
import base64

from node.server import app
from core.identity import PublicKey
from core.seal import Seal
from storage.db import Database, get_database

# The TestClient from FastAPI simulates a running server.
# There is no need to run the bootstrap.py script manually.
client = TestClient(app)

# This test uses the existing test_db fixture from tests/test_api.py
# If tests/conftest.py were used, these fixtures would be automatically available.
from tests.test_api import test_db

def test_register_new_identity(test_db: Database):
    """
    Tests the /api/register-identity endpoint.
    This demonstrates how to write a test for an API endpoint.
    """
    # 1. Arrange: Create a new identity and seal to register.
    identity = PublicKey.generate("ed25519")
    seal = Seal.generate()

    # The data we will send to the API
    registration_payload = {
        "public_key_pem": identity.key_bytes.decode(),
        "public_key_fingerprint": identity.fingerprint,
        "seal_public_key_pem": seal.get_public_key_bytes().decode(),
        "seal_fingerprint": seal.get_fingerprint()
    }

    # 2. Act: Send a POST request to the endpoint.
    response = client.post("/api/register-identity", json=registration_payload)

    # 3. Assert: Check that the request was successful and the data is correct.
    assert response.status_code == 201
    response_data = response.json()
    assert response_data["message"] == "Identity and initial seal registered successfully."
    assert response_data["public_key_fingerprint"] == identity.fingerprint

    # 4. Verify: Check the database directly to confirm the identity was saved.
    saved_identity = test_db.get_identity(identity.fingerprint)
    assert saved_identity is not None
    assert saved_identity["public_key_fingerprint"] == identity.fingerprint
    
    # Also verify that the seal was authorized for the identity
    authorized_seals = test_db.get_active_seals(identity.fingerprint)
    assert len(authorized_seals) == 1
    assert authorized_seals[0] == seal.get_fingerprint()
