# 🔗 URL Shortener

A fast, lightweight URL shortener built with **Rust**, **Actix-web**, and **SQLite**.

## Features

- ✨ **Create short URLs** from long URLs
- 🎯 **Custom short codes** - use your own memorable codes
- ⏰ **Expiring URLs** - set expiration time in hours
- 📊 **Click tracking** - track how many times each URL is accessed
- 📈 **Analytics** - view click logs with IP, user agent, and referer
- 🔐 **Per-user authentication** - email registration with API key management
- 🔑 **Multiple API keys** - create, list, and revoke API keys per user
- 👤 **URL ownership** - users can only access their own URLs
- 📦 **Bulk operations** - create or delete up to 100 URLs in a single request
- 🏷️ **Tags/Categories** - organize URLs with user-defined tags
- 🛡️ **Rate limiting** - 60 requests/minute per IP to prevent abuse
- ⚡ **In-memory caching** - moka-based caching for URL redirects and API key validation
- 🚀 **Blazing fast** - built with Rust and Actix-web
- 💾 **SQLite storage** - no database server required
- ⚡ **WAL mode** - SQLite Write-Ahead Logging for better concurrency
- 🔒 **Atomic operations** - transaction-based click recording for data consistency

## Learning Concepts

This project demonstrates:

1. **Routing** - RESTful API design with Actix-web
2. **IDs & Short Codes** - Generating unique, URL-safe identifiers with nanoid
3. **Persistence** - SQLite database with connection pooling (r2d2)
4. **Error Handling** - Custom error types with proper HTTP responses
5. **Validation** - Input validation with the validator crate
6. **Middleware** - Logging and rate limiting middleware
7. **Rate Limiting** - Request throttling with actix-governor
8. **Database Optimization** - WAL mode for concurrent read/write performance
9. **Transactions** - Atomic operations for data consistency
10. **Authentication** - Per-user API key authentication with SHA-256 hashing
11. **Authorization** - Resource ownership and access control
12. **Caching** - In-memory caching with TTL and automatic invalidation
13. **Testing** - Unit and integration tests

## Project Structure

```
url-shortener/
├── Cargo.toml              # Dependencies and project metadata
├── .env                    # Environment configuration
├── .env.example            # Example configuration
├── .gitignore              # Git ignore rules
├── README.md               # This file
└── src/
    ├── main.rs             # Application entry point and server setup
    ├── config.rs           # Configuration management
    ├── db.rs               # Database pool, WAL configuration, and migrations
    ├── cache.rs            # In-memory caching for URLs and API keys
    ├── models.rs           # Data structures and DTOs
    ├── errors.rs           # Custom error types and HTTP response mapping
    ├── queries.rs          # SQL query constants
    ├── services.rs         # Business logic layer
    ├── handlers.rs         # HTTP route handlers
    └── auth.rs             # API key authentication extractor
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

### Authentication

All `/api/*` endpoints (except `/api/auth/register`) require authentication via API key.

**Provide the API key using one of these headers:**
- `X-API-Key: usk_your_key_here`
- `Authorization: Bearer usk_your_key_here`

---

### Register User (Public)

```bash
POST /api/auth/register
Content-Type: application/json

{
    "email": "user@example.com"
}
```

**Response (201 Created):**
```json
{
    "user_id": 1,
    "email": "user@example.com",
    "api_key": "usk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
}
```

> ⚠️ **Save your API key!** It is only shown once at registration.

---

### Create API Key (Authenticated)

```bash
POST /api/auth/keys
X-API-Key: usk_your_key_here
Content-Type: application/json

{
    "name": "CI/CD key"
}
```

**Response (201 Created):**
```json
{
    "id": 2,
    "name": "CI/CD key",
    "api_key": "usk_x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4",
    "created_at": "2024-01-01 12:00:00"
}
```

---

### List API Keys (Authenticated)

```bash
GET /api/auth/keys
X-API-Key: usk_your_key_here
```

**Response (200 OK):**
```json
{
    "keys": [
        {
            "id": 1,
            "name": "Default key",
            "created_at": "2024-01-01 12:00:00",
            "last_used_at": "2024-01-15 08:30:00",
            "is_active": true
        }
    ]
}
```

---

### Revoke API Key (Authenticated)

```bash
DELETE /api/auth/keys/{id}
X-API-Key: usk_your_key_here
```

**Response (200 OK):**
```json
{
    "message": "API key revoked successfully"
}
```

---

### Create Short URL (Authenticated)

```bash
POST /api/shorten
X-API-Key: usk_your_key_here
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

---

### Redirect to Original URL (Public)

```bash
GET /{short_code}
```

**Response:** 301 Permanent Redirect to the original URL

---

### List Your URLs (Authenticated)

```bash
GET /api/urls?page=1&limit=20&sort=desc
X-API-Key: usk_your_key_here
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

> Note: Only returns URLs owned by the authenticated user.

---

### Get URL Details (Authenticated)

```bash
GET /api/urls/{id}
X-API-Key: usk_your_key_here
```

---

### Get URL Statistics (Authenticated)

```bash
GET /api/urls/{id}/stats
X-API-Key: usk_your_key_here
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

---

### Delete URL (Authenticated)

```bash
DELETE /api/urls/{id}
X-API-Key: usk_your_key_here
```

---

### Bulk Create URLs (Authenticated)

Create multiple URLs in a single request (max 100).

```bash
POST /api/urls/bulk
X-API-Key: usk_your_key_here
Content-Type: application/json

{
    "urls": [
        { "url": "https://example1.com", "custom_code": "ex1" },
        { "url": "https://example2.com", "expires_in_hours": 24 },
        { "url": "https://example3.com" }
    ]
}
```

**Response (201 Created - all succeeded):**
```json
{
    "status": "success",
    "total": 3,
    "succeeded": 3,
    "failed": 0,
    "results": [
        { "index": 0, "success": true, "data": { "short_code": "ex1", ... } },
        { "index": 1, "success": true, "data": { "short_code": "a1b2c3d", ... } },
        { "index": 2, "success": true, "data": { "short_code": "x9y8z7w", ... } }
    ]
}
```

**Response (207 Multi-Status - partial success):**
```json
{
    "status": "partial_success",
    "total": 2,
    "succeeded": 1,
    "failed": 1,
    "results": [
        { "index": 0, "success": true, "data": { ... } },
        { "index": 1, "success": false, "error": { "code": "DUPLICATE_CODE", "message": "..." } }
    ]
}
```

---

### Bulk Delete URLs (Authenticated)

Delete multiple URLs by ID in a single request (max 100).

```bash
DELETE /api/urls/bulk
X-API-Key: usk_your_key_here
Content-Type: application/json

{
    "ids": [1, 2, 3]
}
```

**Response (200 OK - all succeeded):**
```json
{
    "status": "success",
    "total": 3,
    "succeeded": 3,
    "failed": 0,
    "results": [
        { "id": 1, "success": true },
        { "id": 2, "success": true },
        { "id": 3, "success": true }
    ]
}
```

**Response (207 Multi-Status - partial success):**
```json
{
    "status": "partial_success",
    "total": 3,
    "succeeded": 2,
    "failed": 1,
    "results": [
        { "id": 1, "success": true },
        { "id": 2, "success": true },
        { "id": 999, "success": false, "error": { "code": "NOT_FOUND", "message": "..." } }
    ]
}
```

---

### Create Tag (Authenticated)

```bash
POST /api/tags
X-API-Key: usk_your_key_here
Content-Type: application/json

{
    "name": "Important"
}
```

**Response (201 Created):**
```json
{
    "id": 1,
    "name": "Important",
    "created_at": "2024-01-01 12:00:00"
}
```

---

### List Tags (Authenticated)

```bash
GET /api/tags
X-API-Key: usk_your_key_here
```

**Response (200 OK):**
```json
{
    "tags": [
        { "id": 1, "name": "Important", "created_at": "2024-01-01 12:00:00" },
        { "id": 2, "name": "Work", "created_at": "2024-01-01 12:00:00" }
    ]
}
```

---

### Delete Tag (Authenticated)

```bash
DELETE /api/tags/{id}
X-API-Key: usk_your_key_here
```

**Response (200 OK):**
```json
{
    "message": "Tag deleted successfully"
}
```

> Note: Deleting a tag removes it from all associated URLs.

---

### Add Tag to URL (Authenticated)

```bash
POST /api/urls/{id}/tags
X-API-Key: usk_your_key_here
Content-Type: application/json

{
    "tag_id": 1
}
```

**Response (201 Created):**
```json
{
    "message": "Tag added to URL successfully"
}
```

---

### Remove Tag from URL (Authenticated)

```bash
DELETE /api/urls/{id}/tags/{tag_id}
X-API-Key: usk_your_key_here
```

**Response (200 OK):**
```json
{
    "message": "Tag removed from URL successfully"
}
```

---

### Get URLs by Tag (Authenticated)

```bash
GET /api/tags/{id}/urls
X-API-Key: usk_your_key_here
```

**Response (200 OK):**
```json
{
    "urls": [
        {
            "id": 1,
            "short_code": "abc123",
            "short_url": "http://localhost:8080/abc123",
            "original_url": "https://example.com",
            "clicks": 42,
            "created_at": "2024-01-01 12:00:00",
            "updated_at": "2024-01-15 08:30:00",
            "expires_at": null,
            "tags": [
                { "id": 1, "name": "Important", "created_at": "2024-01-01 12:00:00" }
            ]
        }
    ]
}
```

---

### Health Check (Public)

```bash
GET /health
```

**Response (200 OK):**
```json
{
    "status": "healthy",
    "version": "0.1.0"
}
```

## Error Responses

The API returns consistent error responses with appropriate HTTP status codes:

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | `VALIDATION_ERROR` | Invalid input (bad URL format, invalid custom code) |
| 401 | `UNAUTHORIZED` | Missing or invalid API key |
| 403 | `FORBIDDEN` | Not allowed to access this resource |
| 404 | `NOT_FOUND` | URL or resource not found |
| 409 | `DUPLICATE_CODE` | Custom short code already exists |
| 409 | `EMAIL_ALREADY_EXISTS` | Email is already registered |
| 410 | `EXPIRED_URL` | URL has expired |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error |

**Example error response:**
```json
{
    "error": "Missing API key. Provide via 'Authorization: Bearer <key>' or 'X-API-Key: <key>' header",
    "code": "UNAUTHORIZED"
}
```

## Rate Limiting

The API is protected by rate limiting to prevent abuse:

- **Limit:** 60 requests per minute per IP address
- **Burst:** Up to 60 requests allowed in a burst
- **Response:** Returns `429 Too Many Requests` when limit is exceeded

## Caching

The application uses in-memory caching (via `moka`) to optimize the two most frequently accessed operations:

### Cached Operations

| Operation | Cache Key | TTL | Max Capacity |
|-----------|-----------|-----|--------------|
| URL redirects (`GET /{short_code}`) | `short_code` | 5 min | 10,000 |
| API key validation | `key_hash` | 10 min | 1,000 |

### Cache Behavior

- **Cache Miss**: On first access, data is fetched from the database and stored in cache
- **Cache Hit**: Subsequent requests are served from cache without database queries
- **Automatic Expiration**: Entries expire after their TTL (time-to-live)
- **Memory Bounded**: Cache evicts oldest entries when max capacity is reached

### Cache Invalidation

The cache is automatically invalidated when data changes:

| Operation | Invalidation |
|-----------|--------------|
| URL deleted | Cache entry for that `short_code` removed |
| Bulk URL delete | All affected `short_code` entries removed |
| API key revoked | Cache entry for that `key_hash` removed |
| URL expired | Detected on cache hit, entry removed |

### Performance Benefits

- **Reduced database load**: Hot URLs and frequently-used API keys are served from memory
- **Lower latency**: Cache hits avoid database round-trips
- **Lock-free concurrency**: `moka` provides thread-safe access without locks

## Database Schema

The application uses SQLite with six tables:

**users** - Stores registered users
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `email` | TEXT | Unique email address |
| `created_at` | TEXT | Registration timestamp |

**api_keys** - Stores API keys for authentication
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `user_id` | INTEGER | Foreign key to users |
| `key_hash` | TEXT | SHA-256 hash of API key |
| `name` | TEXT | Human-readable key name |
| `created_at` | TEXT | Creation timestamp |
| `last_used_at` | TEXT | Last usage timestamp |
| `is_active` | INTEGER | Whether key is active (1) or revoked (0) |

**urls** - Stores shortened URLs
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `short_code` | TEXT | Unique short code (indexed) |
| `original_url` | TEXT | Original URL |
| `clicks` | INTEGER | Click counter |
| `created_at` | TEXT | Creation timestamp |
| `updated_at` | TEXT | Last update timestamp |
| `expires_at` | TEXT | Optional expiration timestamp |
| `user_id` | INTEGER | Foreign key to users (owner) |

**click_logs** - Stores click analytics
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | Foreign key to urls |
| `clicked_at` | TEXT | Click timestamp |
| `ip_address` | TEXT | Visitor IP address |
| `user_agent` | TEXT | Browser user agent |
| `referer` | TEXT | Referring URL |

**tags** - Stores user-defined tags
| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `name` | TEXT | Tag name (unique per user) |
| `user_id` | INTEGER | Foreign key to users |
| `created_at` | TEXT | Creation timestamp |

**url_tags** - Junction table for URL-tag associations
| Column | Type | Description |
|--------|------|-------------|
| `url_id` | INTEGER | Foreign key to urls |
| `tag_id` | INTEGER | Foreign key to tags |
| PRIMARY KEY | (url_id, tag_id) | Composite key |

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
| `URL_CACHE_TTL_SECS` | `300` | URL cache time-to-live in seconds (5 min) |
| `URL_CACHE_MAX_CAPACITY` | `10000` | Maximum number of URLs to cache |
| `API_KEY_CACHE_TTL_SECS` | `600` | API key cache time-to-live in seconds (10 min) |
| `API_KEY_CACHE_MAX_CAPACITY` | `1000` | Maximum number of API keys to cache |

## Testing with cURL

```bash
# Register a new user (save the api_key from response!)
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Create a short URL (replace YOUR_API_KEY)
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"url": "https://www.rust-lang.org/learn"}'

# Create with custom code
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"url": "https://docs.rs", "custom_code": "docs"}'

# Create with expiration
curl -X POST http://localhost:8080/api/shorten \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"url": "https://temp.example.com", "expires_in_hours": 1}'

# List your URLs
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/urls

# Get URL details
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/urls/1

# Get URL statistics
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/urls/1/stats

# Delete a URL
curl -X DELETE -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/urls/1

# Bulk create URLs
curl -X POST http://localhost:8080/api/urls/bulk \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"urls": [{"url": "https://example1.com"}, {"url": "https://example2.com", "custom_code": "ex2"}]}'

# Bulk delete URLs
curl -X DELETE http://localhost:8080/api/urls/bulk \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"ids": [1, 2, 3]}'

# Test redirect (follow redirects) - no auth needed
curl -L http://localhost:8080/docs

# Create a tag
curl -X POST http://localhost:8080/api/tags \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"name": "Important"}'

# List tags
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/tags

# Add tag to URL
curl -X POST http://localhost:8080/api/urls/1/tags \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"tag_id": 1}'

# Get URLs by tag
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/tags/1/urls

# Remove tag from URL
curl -X DELETE -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/urls/1/tags/1

# Delete tag
curl -X DELETE -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/tags/1

# Create another API key
curl -X POST http://localhost:8080/api/auth/keys \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"name": "Backup key"}'

# List your API keys
curl -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/auth/keys

# Revoke an API key
curl -X DELETE -H "X-API-Key: YOUR_API_KEY" \
  http://localhost:8080/api/auth/keys/2
```

## Adding New Features

Here are some ideas for extending this project:

1. ~~**Authentication** - Add API keys or JWT authentication~~ ✅ Done!
2. **QR Codes** - Generate QR codes for short URLs
3. **Custom Domains** - Support multiple base URLs
4. ~~**Bulk Operations** - Create/delete multiple URLs at once~~ ✅ Done!
5. **Search** - Search URLs by original URL or code
6. ~~**Tags/Categories** - Organize URLs with tags~~ ✅ Done!
7. **Web UI** - Add a frontend with HTML templates or SPA
8. ~~**Caching** - Add Redis or in-memory caching for hot URLs~~ ✅ Done!
9. **Metrics** - Add Prometheus metrics for monitoring
10. **Docker Support** - Add Dockerfile and docker-compose for deployment

## Dependencies

| Crate | Purpose |
|-------|---------|
| `actix-web` | Web framework |
| `actix-governor` | Rate limiting middleware |
| `rusqlite` | SQLite database |
| `r2d2` | Connection pooling |
| `serde` | Serialization |
| `serde_json` | JSON support |
| `nanoid` | Short code generation |
| `chrono` | Date/time handling |
| `validator` | Input validation |
| `thiserror` | Error handling |
| `env_logger` | Logging |
| `url` | URL parsing and validation |
| `regex` | Regular expressions |
| `lazy_static` | Lazy static initialization |
| `sha2` | SHA-256 hashing for API keys |
| `rand` | Random generation for API keys |
| `moka` | In-memory caching with TTL support |

## License

MIT License - feel free to use this project for learning and building!
