# Acounter Core - API Gateway

This is the core backend system for the extensible accounting automation platform, focusing on a robust API Gateway implementation with authentication support.

## Project Overview

The API Gateway is the central entry point for all external requests to the accounting system. It handles:

- Request routing and validation
- Authentication and authorization
- Rate limiting and throttling
- Logging and request tracing

## Getting Started

### Prerequisites

- Rust (2021 edition)
- A text editor
- Docker (optional, for containerized deployment)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/acounter-core
cd acounter-core
```

2. Create a `.env` file based on the provided example:

```bash
cp .env.example .env
```

3. Edit the `.env` file to configure your environment settings.

4. Build the project:

```bash
cargo build
```

### Running the Server

Start the server with:

```bash
cargo run
```

The server will be available at http://127.0.0.1:8080 (or the host/port you configured).

### Running the Tests

Run the integration tests with:

```bash
cargo test
```

## API Documentation

### Authentication

#### Login

```
POST /auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin123
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

#### Get Current User

```
GET /auth/me
Authorization: Bearer YOUR_TOKEN
```

Response:

```json
{
  "id": "user-uuid",
  "username": "admin",
  "email": "admin@example.com",
  "roles": ["Admin"]
}
```

### Health Checks

#### Health Check

```
GET /health
```

Response:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "development",
  "uptime_seconds": 123,
  "timestamp": 1634567890
}
```

#### Readiness Check

```
GET /ready
```

Response: 200 OK

## Testing with the Client

A test client is provided in the `examples` directory. Run it with:

```bash
cargo run --example test_client
```

The client demonstrates how to:

1. Check server health
2. Authenticate to get a token
3. Use the token to access protected endpoints

## Architecture

The API Gateway is built with the following components:

- **API Router**: Central routing system built with Axum
- **Authentication**: JWT-based authentication with role-based access control
- **Middleware**: Request processing, validation, and rate limiting
- **Error Handling**: Consistent error handling and responses
- **Telemetry**: Logging and request tracing

## Next Steps

Future enhancements will include:

- Integration with databases for user storage
- Additional authentication methods
- More extensive API documentation with OpenAPI/Swagger
- Implementation of other core system components
- Module extension points for future accounting features

## License

This project is licensed under the MIT OR Apache-2.0 License.