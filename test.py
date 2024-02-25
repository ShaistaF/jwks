import pytest
import json
import base64
import time
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from server import create_jwt, JWKSHandler
from http.server import HTTPServer

# Define the test JWT token payload
test_payload = {
    "username": "testuser",
    "exp": int(time.time()) + 3600  # 1-hour expiry
}

# Generate test private and public keys
test_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
test_public_key = test_private_key.public_key()

# Serialize test private key to PEM format
test_private_pem = test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize test public key to PEM format
test_public_pem = test_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Calculate the percentage based on two values
def calculate_percentage(part, whole):
    return (part / whole) * 100

# Create a test server with the JWKSHandler
def create_test_server():
    server_address = ('localhost', 8080)
    httpd = HTTPServer(server_address, JWKSHandler)
    return httpd

# Define a fixture for the test server
@pytest.fixture
def server():
    test_server = create_test_server()
    yield test_server
    test_server.server_close()

# Define a fixture for the test client
@pytest.fixture
def client(server):
    return server

def test_auth(client):
    # Make a POST request to the /auth endpoint
    response = client.do_POST()
    # Assert that the status code of the response is 200
    assert response.status_code == 200
    # Load the response data as JSON
    data = json.loads(response.data.decode())
    # Assert that there is a 'token' key in the response data
    assert 'token' in data

def test_jwks(client):
    # Make a GET request to the /.well-known/jwk.json endpoint
    response = client.do_GET()
    # Assert that the status code of the response is 200
    assert response.status_code == 200
    # Load the response data as JSON
    data = json.loads(response.data.decode())
    # Assert that there is a 'keys' key in the response data
    assert 'keys' in data
    # Assert that the public key in the response matches the test key
    assert data['keys'][0]['n'] == base64.b64encode(test_public_key.public_numbers().n.to_bytes(256, byteorder='big')).decode()
    assert data['keys'][0]['e'] == base64.urlsafe_b64encode(test_public_key.public_numbers().e.to_bytes(4, byteorder='big')).decode()

def test_percentage_calculation():
    # Test percentage calculation function
    part = 30
    whole = 150
    result = calculate_percentage(part, whole)
    assert result == 20  # 30 is 20% of 150

# Run the tests using pytest
if __name__ == '__main__':
    pytest.main(['-vv'])
