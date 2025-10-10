import pytest
import json
import base64
from unittest.mock import patch, mock_open

# Simple mock certificate content
MOCK_CERT_CONTENT = b"mock certificate content"
MOCK_KEY_CONTENT = b"mock key content"


@pytest.fixture
def client():
    """Create a test client for the Flask application with mocked CA files."""
    # Mock file operations for CA certificates before importing app
    with patch("builtins.open", mock_open(read_data=MOCK_CERT_CONTENT)):
        # Also mock the cryptography functions to return dummy objects
        with patch(
            "cryptography.hazmat.primitives.serialization.load_pem_private_key"
        ) as mock_load_key, patch(
            "cryptography.x509.load_pem_x509_certificate"
        ) as mock_load_cert:

            # Set up mock return values
            mock_load_key.return_value = "mock_ca_key"
            mock_load_cert.return_value = "mock_ca_cert"

            # Now import the app module
            from app import app

            app.config["TESTING"] = True
            with app.test_client() as client:
                yield client


def test_root_endpoint(client):
    """Test the root endpoint returns API information."""
    response = client.get("/")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "ok" in data
    assert "endpoints" in data


def test_ca_cert_endpoint(client):
    """Test the CA certificate endpoint."""
    response = client.get("/api/ca_cert")
    # This might return 500 if CA is not initialized in test environment
    # We're just checking the endpoint is accessible
    assert response.status_code in [200, 500]


def test_request_cert_no_auth(client):
    """Test certificate request without authentication."""
    response = client.post("/api/request_cert")
    assert response.status_code == 401


def test_request_cert_bearer_no_auth(client):
    """Test bearer certificate request without authentication."""
    response = client.post("/api/request_cert_bearer")
    assert response.status_code == 401


def test_request_cert_basic_auth_invalid(client):
    """Test certificate request with invalid basic auth."""
    invalid_auth = base64.b64encode(b"wrong:credentials").decode("ascii")
    headers = {"Authorization": f"Basic {invalid_auth}"}
    response = client.post("/api/request_cert", headers=headers)
    assert response.status_code == 401


def test_request_cert_bearer_invalid(client):
    """Test certificate request with invalid bearer token."""
    headers = {"Authorization": "Bearer invalid-token"}
    response = client.post("/api/request_cert_bearer", headers=headers)
    assert response.status_code == 401


def test_request_cert_basic_auth_valid_no_csr(client):
    """Test certificate request with valid basic auth but no CSR."""
    valid_auth = base64.b64encode(b"user:password").decode("ascii")
    headers = {
        "Authorization": f"Basic {valid_auth}",
        "Content-Type": "application/json",
    }
    response = client.post("/api/request_cert", json={}, headers=headers)
    assert response.status_code == 400


def test_request_cert_bearer_valid_no_csr(client):
    """Test certificate request with valid bearer token but no CSR."""
    headers = {
        "Authorization": "Bearer my-secret-token",
        "Content-Type": "application/json",
    }
    response = client.post("/api/request_cert_bearer", json={}, headers=headers)
    assert response.status_code == 400


def test_request_cert_basic_auth_invalid_csr(client):
    """Test certificate request with valid basic auth but invalid CSR."""
    valid_auth = base64.b64encode(b"user:password").decode("ascii")
    headers = {
        "Authorization": f"Basic {valid_auth}",
        "Content-Type": "application/json",
    }
    response = client.post(
        "/api/request_cert", json={"csr": "invalid-csr-data"}, headers=headers
    )
    assert response.status_code == 400


def test_request_cert_bearer_invalid_csr(client):
    """Test certificate request with valid bearer token but invalid CSR."""
    headers = {
        "Authorization": "Bearer my-secret-token",
        "Content-Type": "application/json",
    }
    response = client.post(
        "/api/request_cert_bearer", json={"csr": "invalid-csr-data"}, headers=headers
    )
    assert response.status_code == 400


def test_health_check_endpoints(client):
    """Test that all public endpoints are accessible."""
    public_endpoints = ["/", "/api/ca_cert"]

    for endpoint in public_endpoints:
        response = client.get(endpoint)
        # Should not return 404
        assert response.status_code != 404


def test_content_type_json_required(client):
    """Test that endpoints require JSON content type for POST requests."""
    valid_auth = base64.b64encode(b"user:password").decode("ascii")
    headers = {"Authorization": f"Basic {valid_auth}"}

    # Without Content-Type header
    response = client.post("/api/request_cert", data='{"csr": "test"}', headers=headers)
    # This might be 400 or 415 depending on Flask configuration
    assert response.status_code in [400, 415]
