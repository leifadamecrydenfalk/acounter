# Accounting Automation System (Developer Guide)

A robust Rust-based backend system for financial automation, accounting integration, and reporting.

## Project Overview

This system provides a comprehensive set of accounting automation tools including financial alerts, revenue data processing, time reporting validation, project budgeting, and a centralized financial data repository.

### Core Features

- **Automated Financial Alerts**: Threshold-based monitoring for key financial metrics
- **Revenue & User Acquisition Data Automation**: Data pipelines for ad networks with reconciliation
- **Time Report Validation**: Validation engine to identify time reporting errors
- **Project Budgeting & Tracking**: Enhanced budgeting with version control and Fortnox integration
- **Centralized Financial Data Repository**: Secure data warehouse with reporting capabilities
- **Intelligent Time Reporting**: Pattern detection for time entry anomalies

## Technical Architecture

![System Architecture](docs/images/architecture.png)

The system follows a modular architecture with:

- **API Gateway**: Entry point for all external requests
- **Authentication & Authorization**: Secure access control
- **Functional Modules**: Independent, self-contained feature implementations
- **Common Services**: Shared functionality (notifications, scheduling, etc.)
- **Data Storage**: Postgres for structured data, time series for metrics

## Development Setup

### Prerequisites

- Rust (1.67+)
- PostgreSQL (14+)
- Docker & Docker Compose (for containerized development)
- Git

### Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/company/accounting-automation.git
   cd accounting-automation
   ```

2. Set up environment variables (copy from template):
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

3. Run database migrations:
   ```bash
   cargo install sqlx-cli
   sqlx migrate run
   ```

4. Build the project:
   ```bash
   cargo build
   ```

5. Run tests:
   ```bash
   cargo test
   ```

6. Start the development server:
   ```bash
   cargo run
   ```

### Docker Setup

For containerized development:

```bash
docker-compose up -d
```

## Development Workflow

### Branch Strategy

- `main`: Production-ready code
- `develop`: Integration branch for features
- `feature/*`: Individual feature branches
- `fix/*`: Bug fix branches
- `release/*`: Release preparation branches

### Commit Guidelines

Please follow conventional commit messages:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Adding or modifying tests
- `refactor:` - Code changes that neither fix nor add features
- `chore:` - Changes to the build process or auxiliary tools

### Pull Request Process

1. Ensure your code passes all tests and linting
2. Update documentation if necessary
3. Add relevant tests for new functionality
4. Submit PR against the `develop` branch
5. Pass code review
6. Maintainers will merge after approval

## Project Structure

```
.
├── src/
│   ├── alerts/           # Financial alerts module
│   ├── api/              # API endpoints
│   ├── common/           # Shared utilities
│   │   ├── notification/ # Notification services
│   │   ├── scheduler/    # Task scheduling
│   │   └── audit/        # Audit logging
│   ├── config/           # Configuration handling
│   ├── integrations/     # External system integrations
│   │   ├── fortnox/      # Fortnox accounting API
│   │   ├── spreadsheet/  # Spreadsheet connector
│   │   └── ad_networks/  # Ad network integrations
│   ├── revenue/          # Revenue tracking module
│   ├── time/             # Time reporting module
│   └── main.rs           # Application entry point
├── migrations/           # Database migrations
├── tests/                # Integration tests
├── Cargo.toml            # Project dependencies
├── Dockerfile            # Container definition
└── docker-compose.yml    # Development environment
```

## Testing

### Unit Tests

Run unit tests with:

```bash
cargo test
```

### Integration Tests

Integration tests run against a test database:

```bash
cargo test --test '*'
```

### Test Coverage

Generate test coverage reports:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin
```

## API Documentation

API documentation is automatically generated using OpenAPI/Swagger:

```bash
cargo run -- --generate-docs
```

View the docs at `http://localhost:8080/api/docs` when the server is running.

## Performance Considerations

- Use connection pooling for database access
- Implement caching for frequently accessed data
- Leverage Rust's async/await for I/O-bound operations
- Profile performance-critical code paths

## Deployment

See the [Deployment Guide](docs/deployment.md) for detailed instructions on:
- Containerization
- Database setup
- Environment configuration
- Monitoring setup
- Scaling considerations

## Troubleshooting

### Common Issues

#### Database Connection Failures

Check your `.env` file for correct database configuration and ensure PostgreSQL is running.

#### API Authentication Issues

Verify JWT secret configuration and token expiration times.

#### Slow Performance

Enable logging with `RUST_LOG=debug` to identify bottlenecks.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the [MIT License](LICENSE).