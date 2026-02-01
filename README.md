# 🔗 URL Shortener

A fast, lightweight URL shortener built with **Rust**, **Actix-web**, and **SQLite**.

## Features

- ✨ **Create short URLs** from long URLs
- 🎯 **Custom short codes** - use your own memorable codes
- ⏰ **Expiring URLs** - set expiration time in hours
- 📊 **Click tracking** - track how many times each URL is accessed
- 📈 **Analytics** - view click logs with IP, user agent, and referer
- 🚀 **Blazing fast** - built with Rust and Actix-web
- 💾 **SQLite storage** - no database server required

## Learning Concepts

This project demonstrates:

1. **Routing** - RESTful API design with Actix-web
2. **IDs & Short Codes** - Generating unique, URL-safe identifiers with nanoid
3. **Persistence** - SQLite database with connection pooling (r2d2)
4. **Error Handling** - Custom error types with proper HTTP responses
5. **Validation** - Input validation with the validator crate
6. **Middleware** - Logging middleware for request tracking
7. **Testing** - Unit and integration tests

## Project Structure

```
url-shortener/
├── Cargo.toml              # Dependencies and project metadata
├── .env                    # Environment configuration
├── .env.example            # Example configuration
├── .gitignore              # Git ignore rules
├── README.md               # This file
└── src/
    ├── main.rs             # Application entry point
    ├── config.rs           # Configuration management
    ├── db.rs               # Database setup and migrations
    ├── models.rs           # Data structures and DTOs
    ├── errors.rs           # Custom error types
    ├── services.rs         # Business logic
    └── handlers.rs         # HTTP route handlers
```

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (1.70 or later)
- [JetBrains RustRover](https://www.jetbrains.com/rust/) or CLion with Rust plugin

## Getting Started

### 1. Clone or Open in RustRover

Open the project folder in JetBrains RustRover.

### 2. Build the Project

```bash
cargo build
```

### 3. Run the Server

```bash
cargo run
```

The server will start at `http://localhost:8080`

### 4. Run Tests

```bash
cargo test
```

## API Reference

### Create Short URL

```bash
POST /api/shorten
Content-Type: application/json

{
    "url": "https://example.com/very/long/url/that/needs/shortening",
    "custom_code": "mylink",      # optional - custom short code
    "expires_in_hours": 24        # optional - URL expiration
}
```

**Response (201 Created):**
```json
{
    "short_code": "mylink",
    "short_url": "http://localhost:8080/mylink",
    "original_url": "https://example.com/very/long/url/that/needs/shortening",
    "created_at": "2024-01-01 12:00:00",
    "expires_at": "2024-01-02 12:00:00"
}
```

### Redirect to Original URL

```bash
GET /{short_code}
```

**Response:** 301 Permanent Redirect to the original URL

### List All URLs

```bash
GET /api/urls?page=1&limit=20&sort=desc
```

**Response (200 OK):**
```json
{
    "total": 42,
    "urls": [
        {
            "id": 1,
            "short_code": "abc123",
            "short_url": "http://localhost:8080/abc123",
            "original_url": "https://example.com",
            "clicks": 150,
            "created_at": "2024-01-01 12:00:00",
            "updated_at": "2024-01-15 08:30:00",
            "expires_at": null
        }
    ]
}
```

### Get URL Details

```bash
GET /api/urls/{id}
```

### Get URL Statistics

```bash
GET /api/urls/{id}/stats
```

**Response (200 OK):**
```json
{
    "url": { ... },
    "recent_clicks": [
        {
            "id": 1,
            "url_id": 1,
            "clicked_at": "2024-01-15 08:30:00",
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0...",
            "referer": "https://google.com"
        }
    ]
}
```

### Delete URL

```bash
DELETE /api/urls/{id}
```

### Health Check

```bash
GET /health
```

## Configuration

Environment variables (set in `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `urls.db` | SQLite database file path |
| `HOST` | `127.0.0.1` | Server host address |
| `PORT` | `8080` | Server port |
| `BASE_URL` | `http://localhost:8080` | Base URL for generated short links |
| `SHORT_CODE_LENGTH` | `7` | Length of auto-generated codes |
| `RUST_LOG` | `info` | Logging level (debug, info, warn, error) |

## Testing with cURL

```bash
# Create a short URL
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.rust-lang.org/learn"}'

# Create with custom code
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://docs.rs", "custom_code": "docs"}'

# Create with expiration
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://temp.example.com", "expires_in_hours": 1}'

# List all URLs
curl http://localhost:8080/api/urls

# Get URL details
curl http://localhost:8080/api/urls/1

# Get URL statistics
curl http://localhost:8080/api/urls/1/stats

# Delete a URL
curl -X DELETE http://localhost:8080/api/urls/1

# Test redirect (follow redirects)
curl -L http://localhost:8080/docs
```

## Adding New Features

Here are some ideas for extending this project:

1. **Rate Limiting** - Prevent abuse with request rate limiting
2. **Authentication** - Add API keys or JWT authentication
3. **QR Codes** - Generate QR codes for short URLs
4. **Custom Domains** - Support multiple base URLs
5. **Bulk Operations** - Create/delete multiple URLs at once
6. **Search** - Search URLs by original URL or code
7. **Tags/Categories** - Organize URLs with tags
8. **Web UI** - Add a frontend with HTML templates or SPA

## Dependencies

| Crate | Purpose |
|-------|---------|
| `actix-web` | Web framework |
| `rusqlite` | SQLite database |
| `r2d2` | Connection pooling |
| `serde` | Serialization |
| `nanoid` | Short code generation |
| `chrono` | Date/time handling |
| `validator` | Input validation |
| `thiserror` | Error handling |
| `env_logger` | Logging |

## License

MIT License - feel free to use this project for learning and building!
