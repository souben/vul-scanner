# Vulnerability Scanner

A Go-based application with a single Go service with two REST APIs:
- Scan the GitHub repository (https://github.com/velancio/vulnerability_scans) for security vulnerability data stored in JSON files. It extracts the vulnerability information, processes it, and stores it in a structured database.
- Users can then query the stored vulnerabilities by severity level.

## Features

- Scan the GitHub repository (https://github.com/velancio/vulnerability_scans) for vulnerability data in JSON files
- Process multiple files concurrently for improved performance
- Store vulnerability data in a PostgreSQL database
- Query vulnerabilities by severity (e.g HIGH)
- Configurable concurrency and retry mechanisms
- Docker support

## Architecture

The application follows a layered architecture:

- **Controller Layer**: Handles HTTP requests and responses
- **Service Layer**: Contains business logic for scanning and filtering
- **Repository Layer**: Manages database operations
- **Model Layer**: Defines data structures

## API Endpoints

### Scan Repository

```
POST /scan
```

Request body:
```json
{
  "repo": "owner/repo",
  "files": ["optional_filename1", "optional_filename2"]
}
```

Response:
```json
{
  "processed_files": 1,
  "scan_time": "2025-03-18T12:00:00Z",
  "source_repo": "owner/repo",
  "source_files": ["vulnerabilities.json"]
}
```

### Query Vulnerabilities

```
POST /query
```

Request body:
```json
{
  "filters": {
    "severity": "HIGH"
  }
}
```

Response:
```json
[
  {
    "id": "CVE-2024-1234",
    "severity": "HIGH",
    "cvss": 8.5,
    "status": "fixed",
    "package_name": "test-package",
    "current_version": "1.0.0",
    "fixed_version": "1.1.0",
    "description": "Test vulnerability",
    "published_date": "2024-01-01T00:00:00Z",
    "link": "https://example.com/cve",
    "risk_factors": ["Test Risk"],
    "source_file": "test.json",
    "scan_time": "2025-03-18T12:00:00Z"
  }
]
```

## Installation

### Prerequisites
- GitHub API token with repo access (set in the .env file)
- Docker

### Setting Up Environment Variables

Copy the example environment file:

```bash
cp example-env.sh .env
```

Update the variables in `.env` with your configuration:

```
# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=vulnerabilities
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=vulnerabilities

# GitHub API Configuration
GITHUB_API=https://api.github.com/search/code
GITHUB_API_TOKEN=your_github_token_here

# Application Configuration
MAX_RETRIES=2
CONCURRENCY=3
PORT=8080
```

### Running with Docker

```bash
# Build the Docker image
docker compose up --build
```

## Testing

### Running Automated Tests

```bash
# Run all tests
go test ./...

# Run specific package tests with verbose output
go test -v ./service
```

### Try usign the API with CURL

#### Scan Endpoint

```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "velancio/vulnerability_scans",
    "files": ["vulnscan1011"]
  }'
```

#### Query Endpoint

```bash
curl -X POST http://localhost:8080/query \
  -H "Content-Type: application/json" \
  -d '{
    "filters": {
      "severity": "HIGH"
    }
  }'
```


## Configuration Options
- **MAX_RETRIES**: Number of retry attempts for GitHub API calls (default: 2)
- **CONCURRENCY**: Number of concurrent file processing goroutines (default: 3)
- **PORT**: Application HTTP port (default: 8080)
