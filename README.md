# CA Demo API

[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0.3-green.svg)](./docs/api-spec.yaml)
[![Documentation](https://img.shields.io/badge/Documentation-Swagger%20UI-blue.svg)](https://pe-pe.github.io/ca-demo-api/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Flask-based Certificate Authority (CA) demo application that provides API based certificate signing services with multiple authentication methods.

>
> **⚠️ SECURITY WARNING: TESTING PURPOSES ONLY**
>
> This application is designed **ONLY for testing and demonstration purposes**.
> **DO NOT use this in production environments.**
>


## 💡 Motivation

This project was created to provide a simple HTTP endpoint for integrating with custom certificate issuers in [cert-manager](https://cert-manager.io/). It can be used for testing cert-manager configurations and custom issuer implementations.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/pe-pe/ca-demo-api.git
cd ca-demo-api

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## 📖 API Documentation

### Interactive Documentation
- **Swagger UI**: [View Interactive Docs](https://pe-pe.github.io/ca-demo-api/) (GitHub Pages)
- **OpenAPI Spec**: [api-spec.yaml](./docs/api-spec.yaml)


## 🔐 Authentication

The API supports two authentication methods:

### 1. Basic Authentication
- **Username**: `user` (configurable via `BASIC_USER` env var)
- **Password**: `password` (configurable via `BASIC_PASS` env var)
- **Header**: `Authorization: Basic <base64(username:password)>`

### 2. Bearer Token
- **Token**: `my-secret-token` (configurable via `BEARER_TOKEN` env var)
- **Header**: `Authorization: Bearer <token>`

## 📋 API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `GET` | `/` | None | Get API information |
| `GET` | `/api/ca_cert` | None | Retrieve CA certificate |
| `POST` | `/api/request_cert` | Basic Auth | Request certificate signing |
| `POST` | `/api/request_cert_bearer` | Bearer Token | Request certificate signing |

## 🔧 Certificate Signing Request (CSR) Formats

The API accepts CSRs in multiple formats:

### 1. Direct PEM Format
```json
{
  "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20...\n-----END CERTIFICATE REQUEST-----"
}
```

### 2. Base64 Encoded PEM
```json
{
  "CSR": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1dqQ0NBVUlDQVFBd0ZURVRNQKVA..."
}
```

### 3. Base64 Encoded DER
```json
{
  "CSR": "MIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3..."
}
```

## ⏱️ Certificate Validity Duration

You can optionally specify the certificate validity period by including a `duration` field in your request:

### Custom Duration (30 days)
```json
{
  "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
  "duration": 30
}
```

### Custom Duration (7 days)
```json
{
  "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
  "duration": 7
}
```

**Notes:**
- `duration` must be a positive integer (accepts numeric strings and floats, converts to integer)
- `duration` represents the validity period in days
- If not specified, defaults to the value of `DEFAULT_CERT_VALIDITY_DAYS` environment variable (365 days)

## 📝 Example Usage

### Get CA Certificate
```bash
curl -X GET http://localhost:5000/api/ca_cert
```

### Request Certificate (Basic Auth)
```bash
curl -X POST http://localhost:5000/api/request_cert \
  -u user:password \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----"
  }'
```

### Request Certificate with Custom Duration (Basic Auth)
```bash
curl -X POST http://localhost:5000/api/request_cert \
  -u user:password \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
    "duration": 90
  }'
```

### Request Certificate (Bearer Token)
```bash
curl -X POST http://localhost:5000/api/request_cert_bearer \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----"
  }'
```

### Request Certificate with Custom Duration (Bearer Token)
```bash
curl -X POST http://localhost:5000/api/request_cert_bearer \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "CSR": "-----BEGIN CERTIFICATE REQUEST-----\nYOUR_CSR_HERE\n-----END CERTIFICATE REQUEST-----",
    "duration": 7
  }'
```

## ⚠️ Error Responses

| Status Code | Description | Example Response |
|-------------|-------------|------------------|
| `400` | Bad Request | `{"error": "missing csr field (PEM or base64 DER) in JSON body"}` |
| `401` | Unauthorized | `Unauthorized` |
| `500` | Internal Server Error | `{"error": "Failed to sign certificate: ..."}` |

## 🛠️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASIC_USER` | `user` | Username for Basic Authentication |
| `BASIC_PASS` | `password` | Password for Basic Authentication |
| `BEARER_TOKEN` | `my-secret-token` | Token for Bearer Authentication |
| `DEFAULT_CERT_VALIDITY_DAYS` | `365` | Default certificate validity period in days |

## 🐳 Docker Usage

```bash
# Build the image
docker build -t ca-demo-api .

# Run the container
docker run -p 5000:5000 \
  -e BASIC_USER=myuser \
  -e BASIC_PASS=mypassword \
  -e BEARER_TOKEN=my-secure-token \
  -e DEFAULT_CERT_VALIDITY_DAYS=30 \
  ca-demo-api
```

## 📊 Certificate Details

- **Validity**: Configurable (default: 365 days from signing)
  - Can be overridden per request using the `duration` parameter
  - Default can be changed via `DEFAULT_CERT_VALIDITY_DAYS` environment variable
- **Algorithm**: SHA256
- **Extensions**: Copied from CSR when possible
- **Serial Number**: Randomly generated

## 🔗 Links

- [OpenAPI Specification](./docs/api-spec.yaml)
- [Interactive Documentation](https://pe-pe.github.io/ca-demo-api/)

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.
