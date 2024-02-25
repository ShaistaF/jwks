import http.server
import json
import base64
import time
import hashlib
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PORT = 8080

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Extract the public key from the private key
public_key = private_key.public_key()

# Serialize public key to PEM format
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

kid = "my_kid"
expiry = int(time.time()) + 3600  # 1-hour expiry for the key
expired_kid = "expired_kid"
expired_expiry = int(time.time()) - 3600  # Already expired

def create_jwt(payload, private_key, expired=False):
    header = {
        "alg": "RS256",  # Use RS256 algorithm for signing
        "typ": "JWT",
        "kid": expired_kid if expired else kid
    }
    # Encode header and payload without padding
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()

    # Create the signature part
    signing_input = f"{header_encoded}.{payload_encoded}"
    signature = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())

    # Encode the signature part without padding
    signature_encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    # Combine header, payload, and signature with periods
    jwt_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
    return jwt_token


class JWKSHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/jwk.json":
            if expiry < time.time():
                self.send_response(410)  # HTTP 410 Gone
                self.end_headers()
                return

            jwk = {
                "kty": "RSA",
                "kid": kid,
                "n": base64.b64encode(public_key.public_numbers().n.to_bytes(256, byteorder='big')).decode(),
                "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(4, byteorder='big')).decode()
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(jwk).encode())
        else:
            self.send_method_not_allowed()

    def do_POST(self):
        if self.path == "/auth":
            parsed_path = urlparse(self.path)
            query_components = parse_qs(parsed_path.query)
            expired_requested = "expired" in query_components

            # Check if an expired token is requested
            if expired_requested:
                payload = {
                    "username": "userABC",
                    "exp": expired_expiry
                }
            else:
                payload = {
                    "username": "userABC",
                    "exp": expiry
                }

            jwt_token = create_jwt(payload, private_key, expired_requested)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"token": jwt_token}).encode())
        else:
            self.send_method_not_allowed()

    def send_method_not_allowed(self):
        self.send_response(405)  # Method Not Allowed
        self.end_headers()

    def do_PUT(self):
        self.send_method_not_allowed()

    def do_DELETE(self):
        self.send_method_not_allowed()

    def do_PATCH(self):
        self.send_method_not_allowed()

    def do_HEAD(self):
        self.send_method_not_allowed()

if __name__ == "__main__":
    server_address = ('', PORT)
    httpd = http.server.HTTPServer(server_address, JWKSHandler)
    print(f"Server started on port {PORT}")
    httpd.serve_forever()
