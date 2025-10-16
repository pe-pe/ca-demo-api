# CA Demo API

[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0.3-green.svg)](./docs/api-spec.yaml)
[![Documentation](https://img.shields.io/badge/Documentation-Swagger%20UI-blue.svg)](https://pe-pe.github.io/ca-demo-api/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Flask-based Certificate Authority (CA) demo application that provides HTTP-based certificate signing services with multiple authentication methods for testing and development purposes.

> **⚠️ SECURITY WARNING: TESTING PURPOSES ONLY**
>
> This application is designed **ONLY for testing and demonstration purposes**.
> **DO NOT use this in production environments.**

## Motivation

This project was created to provide a simple HTTP endpoint for testing and demonstrating certificate authority integrations, particularly with custom certificate issuers in [cert-manager](https://cert-manager.io/). It serves as a reference implementation for CA APIs and can be used for:

- Testing cert-manager configurations and custom issuer implementations
- Demonstrating HTTP-based certificate signing workflows
- Development and testing of certificate management systems
- Educational purposes for understanding CA operations

## Features

- **HTTP-based Certificate Signing**: RESTful API for certificate signing operations
- **Multiple Authentication Methods**: Basic Auth and Bearer Token authentication
- **Flexible CSR Format Support**: Accepts PEM, Base64 encoded PEM, and Base64 encoded DER formats
- **Configurable Certificate Validity**: Customizable certificate duration per request
- **OpenAPI Documentation**: Complete API specification with interactive documentation
- **Docker Support**: Ready-to-use Docker container for easy deployment
- **Environment Configuration**: Configurable via environment variables

## Quick Start

### Docker Deployment

```bash
# Run latest available image with default parameters
docker run -p 5000:5000 ghcr.io/pe-pe/ca-demo-api:latest
# Build and run with Docker
docker build -t ca-demo-api .
docker run -p 5000:5000 ca-demo-api
```

### Local Development

```bash
# Clone the repository
git clone https://github.com/pe-pe/ca-demo-api.git
cd ca-demo-api
# Install dependencies
pip install -r requirements.txt
# Run the application
python app.py
```

The API will be available at `http://localhost:5000`

## API Documentation

**Interactive Documentation:**
- **Swagger UI**: [View Interactive Docs](https://pe-pe.github.io/ca-demo-api/) (GitHub Pages)
- **OpenAPI Spec**: [api-spec.yaml](./docs/api-spec.yaml)


## Authentication

The API supports two authentication methods for certificate signing operations:

### Basic Authentication
- **Username**: `user` (configurable via `BASIC_USER` environment variable)
- **Password**: `password` (configurable via `BASIC_PASS` environment variable)
- **Header Format**: `Authorization: Basic <base64(username:password)>`

### Bearer Token Authentication
- **Token**: `my-secret-token` (configurable via `BEARER_TOKEN` environment variable)
- **Header Format**: `Authorization: Bearer <token>`

## API Endpoints

| Method | Endpoint | Authentication | Description |
|--------|----------|----------------|-------------|
| `GET` | `/` | None | API information and health status |
| `GET` | `/api/ca_cert` | None | Retrieve CA certificate in PEM format |
| `POST` | `/api/request_cert` | Basic Auth | Request certificate signing with Basic Authentication |
| `POST` | `/api/request_cert_bearer` | Bearer Token | Request certificate signing with Bearer Token |

## Certificate Signing Requests (CSR)

The API accepts Certificate Signing Requests in multiple formats for maximum compatibility:

### Supported CSR Formats

**1. Direct PEM Format**
```json
{
  "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20...\n-----END CERTIFICATE REQUEST-----"
}
```

**2. Base64 Encoded PEM**
```json
{
  "CSR": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1dqQ0NBVUlDQVFBd0ZURVRNQKFA..."
}
```

**3. Base64 Encoded DER**
```json
{
  "CSR": "MIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3..."
}
```

### Certificate Validity Duration

You can optionally specify the certificate validity period by including a `duration` field in your request:

**Custom Duration Examples:**

30 days (43200 minutes):
```json
{
  "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
  "duration": 43200
}
```

7 days (10080 minutes):
```json
{
  "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
  "duration": 10080
}
```

**Duration Field (Optional):**
- Must be a positive integer (accepts numeric strings and floats, converts to integer)
- Represents the validity period in minutes from the time of signing
- If not specified, defaults to `DEFAULT_CERT_VALIDITY_MINUTES` environment variable (525600 minutes = 365 days)

## Usage Examples

### Retrieve CA Certificate

```bash
curl -X GET http://localhost:5000/api/ca_cert
```

### Certificate Signing with Basic Authentication

**Standard Request:**
```bash
curl -X POST http://localhost:5000/api/request_cert \
  -u user:password \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----"
  }'
```

**Request with Custom Duration (90 days):**
```bash
curl -X POST http://localhost:5000/api/request_cert \
  -u user:password \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
    "duration": 129600
  }'
```

### Certificate Signing with Bearer Token Authentication

**Standard Request:**
```bash
curl -X POST http://localhost:5000/api/request_cert_bearer \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----"
  }'
```

**Request with Custom Duration (7 days):**
```bash
curl -X POST http://localhost:5000/api/request_cert_bearer \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
    "duration": 10080
  }'
```

## Error Responses

| Status Code | Description | Example Response |
|-------------|-------------|------------------|
| `400` | Bad Request - Invalid or missing CSR | `{"error": "missing csr field (PEM or base64 DER) in JSON body"}` |
| `401` | Unauthorized - Invalid credentials | `Unauthorized` |
| `500` | Internal Server Error - Certificate signing failure | `{"error": "Failed to sign certificate: ..."}` |

## Configuration

### Environment Variables

| Variable | Default Value | Description |
|----------|---------------|-------------|
| `BASIC_USER` | `user` | Username for Basic Authentication |
| `BASIC_PASS` | `password` | Password for Basic Authentication |
| `BEARER_TOKEN` | `my-secret-token` | Bearer token for token-based authentication |
| `DEFAULT_CERT_VALIDITY_MINUTES` | `525600` | Default certificate validity period in minutes (365 days) |

## Certificate Specifications

### Generated Certificate Properties

- **Signing Algorithm**: SHA256 with RSA
- **Certificate Extensions**: Copied from the original CSR when possible
- **Serial Number**: Randomly generated for each certificate
- **Certificate Format**: X.509 PEM-encoded

### CA Certificate Details

The demo CA uses self-signed certificates for testing purposes. The CA certificate can be retrieved via the `/api/ca_cert` endpoint and used to verify issued certificates.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [cert-manager](https://github.com/cert-manager/cert-manager) - Native Kubernetes certificate management controller
- [HTTP Issuer](https://github.com/pe-pe/http-issuer) - Universal cert-manager issuer for HTTP-based CAs
