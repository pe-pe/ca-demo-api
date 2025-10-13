from flask import Flask, request, jsonify, Response
from functools import wraps
import os
import logging
import time
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S %z",
    format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
BASIC_USER = os.environ.get("BASIC_USER", "user")
BASIC_PASS = os.environ.get("BASIC_PASS", "password")
BEARER_TOKEN = os.environ.get("BEARER_TOKEN", "my-secret-token")
CA_KEY_PATH = "/app/ca/ca.key.pem"
CA_CERT_PATH = "/app/ca/ca.cert.pem"
DEFAULT_CERT_VALIDITY_MINUTES = int(
    os.environ.get("DEFAULT_CERT_VALIDITY_MINUTES", "525600")
)


# Request logging middleware
@app.before_request
def log_request():
    request.start_time = time.time()
    logger.info(
        f"HTTP Request: {request.method} {request.path} from {request.remote_addr} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}"
    )


@app.after_request
def log_response(response):
    duration = time.time() - request.start_time
    logger.info(
        f"HTTP Response: {request.method} {request.path} - Status: {response.status_code} - Duration: {duration:.3f}s"
    )
    return response


with open(CA_KEY_PATH, "rb") as f:
    CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open(CA_CERT_PATH, "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

# --- Basic Auth ---


def check_basic_auth(auth):
    if not auth:
        logger.warning(
            f"Basic auth failed: No credentials provided from {request.remote_addr}"
        )
        return False

    is_valid = auth.username == BASIC_USER and auth.password == BASIC_PASS
    if is_valid:
        logger.info(
            f"Basic auth successful: User '{auth.username}' from {request.remote_addr}"
        )
    else:
        logger.warning(
            f"Basic auth failed: Invalid credentials for user '{auth.username}' from {request.remote_addr}"
        )

    return is_valid


def requires_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not check_basic_auth(auth):
            response = jsonify({"error": "Unauthorized"})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = 'Basic realm="Login Required"'
            return response
        return f(*args, **kwargs)

    return decorated


# --- Bearer Token Auth ---


def requires_bearer_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning(
                f"Bearer token auth failed: Missing or invalid Authorization header format from {request.remote_addr}"
            )
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split()[1] if len(auth_header.split()) > 1 else ""
        if token != BEARER_TOKEN:
            logger.warning(
                f"Bearer token auth failed: Invalid token from {request.remote_addr}"
            )
            return jsonify({"error": "Unauthorized"}), 401

        logger.info(f"Bearer token auth successful from {request.remote_addr}")
        return f(*args, **kwargs)

    return decorated


# --- Certificate Signing Logic ---


def process_cert_request():
    """Common function to handle certificate signing logic."""
    logger.info(
        f"Processing certificate request from {request.remote_addr} with data: {request.get_data(as_text=True)}"
    )

    # Check if request has JSON content
    if not request.is_json:
        error_msg = "Request must contain JSON data"
        logger.error(
            f"Validation error: {error_msg} - Content-Type: {request.content_type}"
        )
        return jsonify({"error": error_msg}), 400

    try:
        data = request.get_json(force=True)
    except Exception as e:
        error_msg = f"Failed to parse JSON data: {str(e)}"
        logger.error(f"JSON parsing error: {error_msg}")
        return jsonify({"error": error_msg}), 400

    if not data:
        error_msg = "Empty or invalid JSON body"
        logger.error(f"Validation error: {error_msg}")
        return jsonify({"error": error_msg}), 400

    if "CSR" not in data:
        error_msg = "missing csr field (PEM or base64 DER) in JSON body"
        logger.error(
            f"Validation error: {error_msg} - Available fields: {list(data.keys())}"
        )
        return jsonify({"error": error_msg}), 400

    csr_pem_str = data["CSR"]
    if not isinstance(csr_pem_str, str):
        error_msg = f"CSR field must be a string, got {type(csr_pem_str).__name__}"
        logger.error(f"Validation error: {error_msg}")
        return jsonify({"error": error_msg}), 400

    if not csr_pem_str.strip():
        error_msg = "CSR field cannot be empty"
        logger.error(f"Validation error: {error_msg}")
        return jsonify({"error": error_msg}), 400

    # Parse optional duration parameter (in minutes)
    validity_minutes = DEFAULT_CERT_VALIDITY_MINUTES
    if "duration" in data:
        try:
            duration_value = data["duration"]
            if duration_value is not None and duration_value > 0:
                validity_minutes = int(duration_value)
                logger.info(
                    f"Using custom certificate validity period: {validity_minutes} minutes"
                )
            else:
                error_msg = "Duration must be a positive number"
                logger.error(f"Validation error: {error_msg}")
                return jsonify({"error": error_msg}), 400
        except (ValueError, TypeError) as e:
            error_msg = f"Invalid duration value: {str(e)}"
            logger.error(f"Validation error: {error_msg}")
            return jsonify({"error": error_msg}), 400
    else:
        logger.info(
            f"Using default certificate validity period: {validity_minutes} minutes"
        )

    logger.debug(f"Attempting to parse CSR of length {len(csr_pem_str)} characters")

    # Try to parse as direct PEM format first
    if csr_pem_str.strip().startswith("-----BEGIN CERTIFICATE REQUEST-----"):
        try:
            csr = x509.load_pem_x509_csr(csr_pem_str.encode("utf-8"))
            logger.info(
                f"Successfully parsed direct PEM CSR - Subject: {csr.subject}, Public key algorithm: {csr.public_key().__class__.__name__}"
            )
        except ValueError as e:
            error_msg = f"Invalid PEM format: {str(e)}"
            logger.error(f"PEM CSR parsing error: {error_msg}")
            return jsonify({"error": f"failed to parse PEM CSR: {error_msg}"}), 400
        except Exception as e:
            error_msg = f"failed to parse PEM CSR: {str(e)}"
            logger.error(f"PEM CSR parsing error: {error_msg}")
            return jsonify({"error": error_msg}), 400
    else:
        # Try to parse as base64 encoded PEM format (entire PEM block is base64 encoded)
        try:
            # Remove any whitespace and decode base64
            csr_base64_clean = "".join(csr_pem_str.split())
            decoded_pem_bytes = base64.b64decode(csr_base64_clean)

            # Check if decoded content is valid PEM
            decoded_pem_str = decoded_pem_bytes.decode("utf-8")
            if decoded_pem_str.strip().startswith(
                "-----BEGIN CERTIFICATE REQUEST-----"
            ):
                csr = x509.load_pem_x509_csr(decoded_pem_bytes)
                logger.info(
                    f"Successfully parsed base64 encoded PEM CSR - Subject: {csr.subject}, Public key algorithm: {csr.public_key().__class__.__name__}"
                )
            else:
                raise ValueError("Decoded content is not a valid PEM format")

        except Exception as base64_pem_error:
            # If base64 encoded PEM parsing fails, try as raw base64 DER format
            try:
                csr_base64_clean = "".join(csr_pem_str.split())
                csr_der = base64.b64decode(csr_base64_clean)
                csr = x509.load_der_x509_csr(csr_der)
                logger.info(
                    f"Successfully parsed base64 DER CSR - Subject: {csr.subject}, Public key algorithm: {csr.public_key().__class__.__name__}"
                )
            except Exception as der_error:
                error_msg = f"Failed to parse CSR in any format. Base64 PEM error: {str(base64_pem_error)}, DER error: {str(der_error)}"
                logger.error(f"CSR parsing error: {error_msg}")
                return (
                    jsonify(
                        {
                            "error": "failed to parse CSR: CSR must be in PEM format, base64 encoded PEM format, or base64 encoded DER format"
                        }
                    ),
                    400,
                )

    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(CA_CERT.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(
            datetime.now(timezone.utc) + timedelta(minutes=validity_minutes)
        )
    )

    try:
        for ext in csr.extensions:
            cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    except Exception as e:
        logger.warning(f"Failed to add some CSR extensions: {str(e)}")

    try:
        cert = cert_builder.sign(private_key=CA_KEY, algorithm=hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        logger.info(f"Successfully signed certificate - Subject: {csr.subject}")
        return Response(cert_pem, mimetype="application/x-pem-file")
    except Exception as e:
        error_msg = f"Failed to sign certificate: {str(e)}"
        logger.error(f"Certificate signing error: {error_msg}")
        return jsonify({"error": error_msg}), 500


# --- Endpoints ---


@app.route("/api/ca_cert", methods=["GET"])
def get_ca_cert():
    logger.info(f"CA certificate requested from {request.remote_addr}")
    try:
        with open(CA_CERT_PATH, "rb") as f:
            pem = f.read()
        logger.info(f"CA certificate served successfully to {request.remote_addr}")
        return Response(pem, mimetype="application/x-pem-file")
    except Exception as e:
        error_msg = f"Failed to read CA certificate: {str(e)}"
        logger.error(error_msg)
        return jsonify({"error": error_msg}), 500


@app.route("/api/request_cert", methods=["POST"])
@requires_basic_auth
def request_cert():
    return process_cert_request()


@app.route("/api/request_cert_bearer", methods=["POST"])
@requires_bearer_token
def request_cert_bearer():
    return process_cert_request()


@app.route("/", methods=["GET"])
def index():
    logger.info(f"Index endpoint accessed from {request.remote_addr}")

    # Generate endpoints list dynamically from Flask's route registry
    endpoints = []
    for rule in app.url_map.iter_rules():
        # Skip static file rules
        if rule.endpoint != "static":
            # Filter out HEAD and OPTIONS methods
            methods = sorted(
                [method for method in rule.methods if method not in ("HEAD", "OPTIONS")]
            )
            for method in methods:
                endpoints.append(f"{method} {rule.rule}")

    return jsonify({"ok": True, "endpoints": sorted(endpoints)})


if __name__ == "__main__":
    logger.info("Starting Flask application on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)
