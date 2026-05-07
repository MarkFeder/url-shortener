# Rust for C++ Programmers

A Study Guide Based on the URL Shortener Project

## Table of Contents

1. [Project Structure & Build System](#1-project-structure--build-system)
2. [Ownership & Borrowing vs RAII](#2-ownership--borrowing-vs-raii)
3. [Error Handling: Result vs Exceptions](#3-error-handling-result-vs-exceptions)
4. [Enums with Data vs `std::variant`](#4-enums-with-data-vs-stdvariant)
5. [Traits vs Virtual Classes](#5-traits-vs-virtual-classes)
6. [Pattern Matching](#6-pattern-matching)
7. [Structs and Methods](#7-structs-and-methods)
8. [String Types](#8-string-types)
9. [`Option` vs `std::optional`](#9-option-vs-stdoptional)
10. [Modules vs Headers](#10-modules-vs-headers)
11. [Iterators and Closures](#11-iterators-and-closures)
12. [Macros and Derive](#12-macros-and-derive)
13. [Async/Await](#13-asyncawait)
14. [Testing](#14-testing)
15. [Concurrency & Thread Safety](#15-concurrency--thread-safety) *(new)*
16. [Custom Extractors and the `FromRequest` Trait](#16-custom-extractors-and-the-fromrequest-trait) *(new)*
17. [Const-Driven Validation with Attribute Macros](#17-const-driven-validation-with-attribute-macros) *(new)*
18. [Avoiding N+1 Queries with `HashMap`](#18-avoiding-n1-queries-with-hashmap) *(new)*
19. [Pagination: `count + list` Split](#19-pagination-count--list-split) *(new)*
20. [Common Gotchas for C++ Programmers](#20-common-gotchas-for-c-programmers)

---

## 1. Project Structure & Build System

### Cargo vs CMake

**C++ (`CMakeLists.txt`):**

```cmake
cmake_minimum_required(VERSION 3.16)
project(url-shortener)

set(CMAKE_CXX_STANDARD 20)

find_package(SQLite3 REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_executable(url-shortener
    src/main.cpp
    src/config.cpp
    src/db.cpp
    src/handlers.cpp
)

target_link_libraries(url-shortener
    SQLite::SQLite3
    Boost::system
)
```

**Rust (`Cargo.toml` from this project):**

```toml
[package]
name = "url-shortener"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
rusqlite = { version = "0.31", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
```

### Key Differences

| Aspect | C++ | Rust |
|---|---|---|
| Package manager | vcpkg/conan/manual | Cargo (built-in) |
| Build system | CMake/Make/Ninja | Cargo (built-in) |
| Dependency declaration | `find_package()` | `[dependencies]` section |
| Feature flags | compile definitions | `features = ["..."]` |

---

## 2. Ownership & Borrowing vs RAII

This is the most important concept for C++ programmers to understand.

### C++ RAII with Smart Pointers

```cpp
class DbPool {
    std::unique_ptr<Connection> conn_;

public:
    DbPool(std::string url) : conn_(std::make_unique<Connection>(url)) {}

    // Copy is deleted (unique_ptr)
    DbPool(const DbPool&) = delete;
    DbPool& operator=(const DbPool&) = delete;

    // Move is allowed
    DbPool(DbPool&&) = default;
    DbPool& operator=(DbPool&&) = default;

    Connection& get() { return *conn_; }
};

void use_pool(DbPool& pool) {        // Borrow by reference
    auto& conn = pool.get();
    // use conn...
}
```

### Rust Ownership (from `infra/db.rs`)

```rust
pub type DbPool = Pool<SqliteConnectionManager>;
pub type DbConnection = PooledConnection<SqliteConnectionManager>;

pub fn get_conn(pool: &DbPool) -> Result<DbConnection, AppError> {
    pool.get()
        .map_err(|e| AppError::DatabaseError(format!("Failed: {}", e)))
}
```

### The Three Rules of Ownership

1. **Each value has exactly one owner** — like `std::unique_ptr`, but enforced at compile time for ALL types.
2. **When the owner goes out of scope, the value is dropped** — same as RAII destructors.
3. **You can have EITHER one mutable reference OR many immutable references** — this is NEW. C++ doesn't enforce this.

### Borrowing Comparison Table

| C++ | Rust | Meaning |
|---|---|---|
| `T` | `T` | Owned value (moved or copied) |
| `T&` | `&T` | Immutable borrow |
| `T&` (non-const) | `&mut T` | Mutable borrow |
| `const T&` | `&T` | Immutable borrow |
| `T*` | `*const T` or `*mut T` | Raw pointer (unsafe) |
| `std::unique_ptr<T>` | `Box<T>` | Heap-allocated owned value |
| `std::shared_ptr<T>` | `Arc<T>` or `Rc<T>` | Reference-counted |

### Example from `services/urls.rs`

```rust
// pool is borrowed immutably (&DbPool)
// request is borrowed immutably (&CreateUrlRequest)
// Returns an owned Url
pub fn create_url(
    pool: &DbPool,
    request: &CreateUrlRequest,
    code_length: usize,
    user_id: i64,
) -> Result<Url, AppError> {
    let conn = get_conn(pool)?; // conn is owned
    // ...
}
```

### C++ Equivalent

```cpp
std::expected<Url, AppError> create_url(
    const DbPool& pool,
    const CreateUrlRequest& request,
    size_t code_length,
    int64_t user_id
) {
    auto conn = get_conn(pool);
    if (!conn) return std::unexpected(conn.error());
    // ...
}
```

---

## 3. Error Handling: Result vs Exceptions

### C++ Traditional Approach (Exceptions)

```cpp
Url get_url_by_code(DbPool& pool, const std::string& code) {
    auto conn = pool.get(); // May throw
    auto stmt = conn.prepare("SELECT...");
    auto row = stmt.query_row(code);
    if (!row) {
        throw NotFoundException("URL not found");
    }
    return Url::from_row(*row);
}

// Caller:
try {
    auto url = get_url_by_code(pool, "abc123");
    // use url...
} catch (const NotFoundException& e) {
    // handle not found
} catch (const DatabaseException& e) {
    // handle db error
}
```

### Rust Approach (`Result<T, E>`)

From `services/urls.rs`:

```rust
pub fn get_url_by_code(pool: &DbPool, short_code: &str) -> Result<Url, AppError> {
    let conn = get_conn(pool)?; // ? propagates error

    let url = conn
        .query_row(Urls::SELECT_BY_CODE, params![short_code], map_url_row)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("URL '{}' not found", short_code))
            }
            _ => AppError::DatabaseError(e.to_string()),
        })?;

    Ok(url)
}
```

### The `?` Operator

```rust
// These are equivalent:
let conn = get_conn(pool)?;

// Desugars to:
let conn = match get_conn(pool) {
    Ok(c) => c,
    Err(e) => return Err(e.into()),
};
```

### Comparison Table

| Aspect | C++ Exceptions | Rust `Result` |
|---|---|---|
| Visibility | Hidden in function signature | Explicit in return type |
| Performance | Zero-cost happy path, expensive throw | Always same cost |
| Propagation | Automatic (invisible) | Explicit with `?` |
| Forcing handling | Not enforced | Compiler warns on unused `Result` |
| Stack unwinding | Yes | No |

### Converting Between Error Types (from `infra/errors.rs`)

```rust
// Implement From trait for automatic conversion
impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        // Map UNIQUE constraint violations to a domain-specific 409 error
        // instead of a generic 500 — concurrent inserts shouldn't surface
        // as server errors.
        if let rusqlite::Error::SqliteFailure(ffi_err, _) = &err {
            if ffi_err.code == rusqlite::ErrorCode::ConstraintViolation {
                return AppError::DuplicateCode(err.to_string());
            }
        }
        log::error!("Database error: {:?}", err);
        AppError::DatabaseError(err.to_string())
    }
}

// Now ? automatically converts rusqlite::Error to AppError
```

### C++23 `std::expected` (similar concept)

```cpp
std::expected<Url, AppError> get_url_by_code(DbPool& pool, std::string_view code) {
    auto conn = pool.get();
    if (!conn) return std::unexpected(AppError::database(conn.error()));
    // ...
}
```

---

## 4. Enums with Data vs `std::variant`

Rust enums are like tagged unions on steroids.

### C++ Approach (`std::variant`)

```cpp
struct NotFound { std::string message; };
struct ValidationError { std::string message; };
struct DatabaseError { std::string message; };
struct DuplicateCode { std::string message; };

using AppError = std::variant<NotFound, ValidationError, DatabaseError, DuplicateCode>;

std::string get_message(const AppError& err) {
    return std::visit([](auto&& arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, NotFound>)
            return "Not found: " + arg.message;
        else if constexpr (std::is_same_v<T, ValidationError>)
            return "Validation: " + arg.message;
        // ... etc
    }, err);
}
```

### Rust Approach (from `infra/errors.rs`)

```rust
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    ValidationError(String),
    DatabaseError(String),
    DuplicateCode(String),
    ExpiredUrl(String),
    InternalError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AppError::DuplicateCode(msg) => write!(f, "Duplicate code: {}", msg),
            AppError::ExpiredUrl(msg) => write!(f, "URL expired: {}", msg),
            AppError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}
```

### Key Differences

| Aspect | C++ `std::variant` | Rust `enum` |
|---|---|---|
| Syntax | Verbose, separate types | Concise, inline variants |
| Pattern matching | `std::visit` + lambdas | `match` expression |
| Exhaustiveness | Not checked | Compiler enforces |
| Method attachment | External functions | `impl` blocks |

---

## 5. Traits vs Virtual Classes

Traits are Rust's approach to polymorphism — similar to C++ concepts but also like interfaces.

### C++ Virtual Classes

```cpp
class Error : public std::exception {
public:
    virtual const char* what() const noexcept = 0;
    virtual int status_code() const = 0;
    virtual HttpResponse error_response() const = 0;
};

class AppError : public Error {
    std::string message_;
public:
    const char* what() const noexcept override { return message_.c_str(); }
    int status_code() const override { return 500; }
    HttpResponse error_response() const override { /*...*/ }
};
```

### Rust Traits (from `infra/errors.rs`)

```rust
// std::error::Error is a trait (like an interface)
impl std::error::Error for AppError {}

// ResponseError is an Actix-web trait
impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::DuplicateCode(_) => StatusCode::CONFLICT,
            AppError::ExpiredUrl(_) => StatusCode::GONE,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .json(ErrorResponse::new(/*...*/))
    }
}
```

### Key Differences

| Aspect | C++ Virtual | Rust Traits |
|---|---|---|
| Dispatch | vtable (runtime) | Static or dynamic (`dyn Trait`) |
| Implementation | In class definition | Separate `impl` block |
| Multiple inheritance | Allowed | Multiple traits allowed |
| Default implementations | Possible | Possible |
| Memory layout | vtable pointer in object | No overhead for static |

### Static vs Dynamic Dispatch

```rust
// Static dispatch (like C++ templates) - no runtime cost
fn process<T: ResponseError>(error: T) { /*...*/ }

// Dynamic dispatch (like C++ virtual) - uses vtable
fn process(error: &dyn ResponseError) { /*...*/ }
```

---

## 6. Pattern Matching

Rust's `match` is far more powerful than C++ `switch`.

### C++ Switch

```cpp
int status_code(const AppError& err) {
    // C++ switch only works on integral types
    // Must use if-else or std::visit for variants
    if (std::holds_alternative<NotFound>(err)) return 404;
    if (std::holds_alternative<ValidationError>(err)) return 400;
    // ...
}
```

### Rust Match (from `infra/errors.rs`)

```rust
fn status_code(&self) -> StatusCode {
    match self {
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
        AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        AppError::DuplicateCode(_) => StatusCode::CONFLICT,
        AppError::ExpiredUrl(_) => StatusCode::GONE,
        AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
```

### Advanced Pattern Matching (from `services/urls.rs`)

```rust
// Matching with destructuring and guards
let short_code = match &request.custom_code {
    Some(code) => {
        if code_exists(&conn, code)? {
            return Err(AppError::DuplicateCode(/*...*/));
        }
        code.clone()
    }
    None => generate_short_code(code_length),
};

// Matching on Result with error transformation
.map_err(|e| match e {
    rusqlite::Error::QueryReturnedNoRows => {
        AppError::NotFound(format!("URL '{}' not found", short_code))
    }
    _ => AppError::DatabaseError(e.to_string()),
})
```

### Pattern Types

| Pattern | Example | C++ Equivalent |
|---|---|---|
| Literal | `5` | `case 5:` |
| Variable | `x` | N/A (binds value) |
| Wildcard | `_` | `default:` |
| Tuple | `(x, y)` | `auto [x, y] = ...` |
| Struct | `Point { x, y }` | Structured bindings |
| Enum | `Some(v)` | `std::get<T>()` |
| Reference | `&val` | N/A |
| Guard | `x if x > 5` | `if`-`else` |
| Or | `1 \| 2 \| 3` | fallthrough |

---

## 7. Structs and Methods

### C++ Class

```cpp
class Config {
    std::string database_url_;
    std::string host_;
    uint16_t port_;

public:
    Config() : database_url_("urls.db"), host_("127.0.0.1"), port_(8080) {}

    static Config from_env() {
        Config c;
        if (auto val = std::getenv("DATABASE_URL")) c.database_url_ = val;
        if (auto val = std::getenv("HOST"))         c.host_ = val;
        if (auto val = std::getenv("PORT"))         c.port_ = std::stoi(val);
        return c;
    }

    const std::string& database_url() const { return database_url_; }
    const std::string& host() const         { return host_; }
    uint16_t port() const                   { return port_; }
};
```

### Rust Struct (from `infra/config.rs`)

```rust
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub short_code_length: usize,
}

impl Config {
    pub fn from_env() -> Self {
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .expect("PORT must be a valid number");

        Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "urls.db".to_string()),
            host,
            port,
            base_url: env::var("BASE_URL")
                .unwrap_or_else(|_| format!("http://{}:{}", host, port)),
            short_code_length: 7,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: "urls.db".to_string(),
            host: "127.0.0.1".to_string(),
            port: 8080,
            base_url: "http://localhost:8080".to_string(),
            short_code_length: 7,
        }
    }
}
```

### Key Differences

| Aspect | C++ | Rust |
|---|---|---|
| Fields | Private by default | Private by default (`pub` for public) |
| Methods | Inside class | In `impl` blocks (can be multiple) |
| Constructors | Constructor functions | Associated functions (no special syntax) |
| `this`/`self` | Implicit `this` pointer | Explicit `self`, `&self`, or `&mut self` |
| Default values | Initializer list | `Default` trait |
| Copy/Clone | Copy constructor | `Clone` trait (explicit) |

### Self Parameter

```rust
impl Config {
    fn consume(self) {}         // Takes ownership (moved)
    fn borrow(&self) {}         // Immutable borrow (const ref)
    fn borrow_mut(&mut self) {} // Mutable borrow
    fn new() -> Self {}         // No self - associated function (static)
}
```

---

## 8. String Types

### C++ Strings

```cpp
std::string owned = "hello";       // Owned, heap-allocated
const char* literal = "hello";     // String literal (static)
std::string_view view = owned;     // Non-owning view
```

### Rust Strings

```rust
let owned: String = "hello".to_string();   // Owned, heap-allocated
let literal: &str = "hello";               // String slice (like string_view)
let slice: &str = &owned[0..3];            // Slice of owned string
```

### Comparison Table

| C++ | Rust | Ownership | Mutability |
|---|---|---|---|
| `std::string` | `String` | Owned | Mutable |
| `const char*` | `&'static str` | Borrowed (static) | Immutable |
| `std::string_view` | `&str` | Borrowed | Immutable |
| `char*` | `&mut str` | Borrowed | Mutable (rare) |

### Common Conversions

```rust
// &str to String
let s: String = "hello".to_string();
let s: String = String::from("hello");
let s: String = "hello".into();

// String to &str
let s: String = String::from("hello");
let slice: &str = &s;
let slice: &str = s.as_str();

// From format! macro (like sprintf)
let s: String = format!("Hello, {}!", name);
```

### Example from `handlers/urls.rs`

```rust
let response = CreateUrlResponse {
    short_code: url.short_code.clone(), // Clone the String
    short_url: format!("{}/{}", config.base_url, url.short_code),
    original_url: url.original_url,     // Move the String
    // ...
};
```

---

## 9. `Option` vs `std::optional`

### C++ `std::optional`

```cpp
std::optional<std::string> get_env(const std::string& key) {
    if (auto val = std::getenv(key.c_str())) {
        return std::string(val);
    }
    return std::nullopt;
}

// Usage
auto val = get_env("PORT");
if (val) {
    std::cout << *val << std::endl;
}
// Or with value_or
auto port = get_env("PORT").value_or("8080");
```

### Rust `Option` (from `models/db.rs`)

```rust
pub struct Url {
    pub id: i64,
    pub short_code: String,
    pub original_url: String,
    pub clicks: i64,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>, // May or may not have expiration
    pub user_id: Option<i64>,
}
```

### Option Methods

```rust
let opt: Option<String> = Some("hello".to_string());

// Check and use
if let Some(val) = opt {
    println!("{}", val);
}

// Or with match
match opt {
    Some(val) => println!("{}", val),
    None => println!("No value"),
}

// Unwrap with default
let val = opt.unwrap_or("default".to_string());
let val = opt.unwrap_or_else(|| compute_default());

// Transform
let upper: Option<String> = opt.map(|s| s.to_uppercase());

// Chain
let len: Option<usize> = opt.as_ref().map(|s| s.len());
```

### Example from `services/urls.rs`

```rust
// Calculate expiration date if specified
let expires_at = request.expires_in_hours.map(|hours| {
    (Utc::now() + Duration::hours(hours))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
});
```

---

## 10. Modules vs Headers

### C++ Headers

```cpp
// config.hpp
#pragma once
#include <string>

class Config {
public:
    static Config from_env();
    // ...
};

// config.cpp
#include "config.hpp"

Config Config::from_env() {
    // implementation
}

// main.cpp
#include "config.hpp"

int main() {
    auto config = Config::from_env();
}
```

### Rust Modules (from `main.rs`)

```rust
mod auth;
mod handlers;
mod infra;
mod models;
mod queries;
mod services;
mod test_utils;

use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = infra::config::Config::from_env();
    // ...
}
```

### Module System (current layout)

```text
src/
  main.rs              // crate root, declares modules
  auth.rs              // AuthenticatedUser extractor
  infra/               // cross-cutting infrastructure
    mod.rs
    cache.rs
    config.rs
    constants.rs
    db.rs
    errors.rs
    metrics.rs
    qr.rs
  models/              // request/response DTOs + DB entities
    mod.rs
    db.rs
    url.rs
    tag.rs
    ...
  queries/             // raw SQL constants
  services/            // business logic
  handlers/            // HTTP endpoints
```

### Visibility

| Rust | C++ | Meaning |
|---|---|---|
| (default) | `private` | Private to module |
| `pub` | `public` | Public |
| `pub(crate)` | (internal linkage) | Public within crate |
| `pub(super)` | N/A | Public to parent module |

### Use Statements (from `services/urls.rs`)

```rust
use chrono::{Duration, Utc};
use rusqlite::params;

use crate::infra::cache::{AppCache, CachedUrl};
use crate::infra::db::{get_conn, DbPool};
use crate::infra::errors::AppError;
use crate::models::{CreateUrlRequest, ListUrlsQuery, UpdateUrlRequest, Url};
use crate::queries::Urls;
```

---

## 11. Iterators and Closures

### C++ Iterators and Lambdas

```cpp
std::vector<Url> urls = get_urls();
std::vector<UrlResponse> responses;
responses.reserve(urls.size());

std::transform(urls.begin(), urls.end(), std::back_inserter(responses),
    [&config](const Url& u) {
        return UrlResponse::from_url(u, config.base_url);
    });
```

### Rust Iterators (from `handlers/urls.rs`)

```rust
let url_responses: Vec<UrlResponse> = urls
    .into_iter()
    .map(|u| UrlResponse::from_url(u, &config.base_url))
    .collect();
```

### Iterator Methods

```rust
let numbers = vec![1, 2, 3, 4, 5];

// Map - transform each element
let doubled: Vec<i32> = numbers.iter().map(|x| x * 2).collect();

// Filter - keep matching elements
let evens: Vec<&i32> = numbers.iter().filter(|x| *x % 2 == 0).collect();

// Find - first matching element
let first_even: Option<&i32> = numbers.iter().find(|x| *x % 2 == 0);

// Fold - reduce to single value (like std::accumulate)
let sum: i32 = numbers.iter().fold(0, |acc, x| acc + x);

// Collect with turbofish for type inference
let set: HashSet<i32> = numbers.into_iter().collect();
```

### Iterator Types

| Method | C++ Equivalent | Ownership |
|---|---|---|
| `.iter()` | `begin()`/`end()` | Borrows (`&T`) |
| `.iter_mut()` | mutable iterators | Borrows mutably (`&mut T`) |
| `.into_iter()` | move iterators | Takes ownership (`T`) |

### Example from `services/urls.rs`

```rust
let urls = stmt
    .query_map(params![user_id, limit, offset], map_url_row)?
    .collect::<Result<Vec<_>, _>>()?; // Collect Results into Result<Vec>
```

---

## 12. Macros and Derive

### C++ Templates/Macros

```cpp
// Template for serialization (complex, lots of boilerplate)
template<typename Archive>
void serialize(Archive& ar, Url& url) {
    ar & url.id & url.short_code & url.original_url;
}

// Or macros (text substitution, limited)
#define DECLARE_SERIALIZABLE(Type) \
    friend class boost::serialization::access; \
    template<class Archive> \
    void serialize(Archive& ar, unsigned int version);
```

### Rust Derive Macros (from `models/db.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Url {
    pub id: i64,
    pub short_code: String,
    pub original_url: String,
    pub clicks: i64,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub user_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUrlRequest {
    #[validate(url(message = "Invalid URL format"))]
    #[validate(length(max = MAX_URL_LENGTH, message = "URL is too long"))]
    pub url: String,

    #[validate(length(min = MIN_CUSTOM_CODE_LENGTH, max = MAX_CUSTOM_CODE_LENGTH))]
    pub custom_code: Option<String>,

    #[validate(custom(function = "validate_positive_hours"))]
    pub expires_in_hours: Option<i64>,
}
```

### Common Derive Macros

| Derive | Purpose | C++ Equivalent |
|---|---|---|
| `Debug` | Debug printing | `operator<<` |
| `Clone` | Deep copy | Copy constructor |
| `Copy` | Bitwise copy | Trivially copyable |
| `PartialEq` | Equality | `operator==` |
| `Eq` | Total equality | `operator==` (strict) |
| `Hash` | Hashing | `std::hash` |
| `Default` | Default values | Default constructor |
| `Serialize` | To JSON/etc | Custom |
| `Deserialize` | From JSON/etc | Custom |

### Attribute Macros (from `handlers/urls.rs`)

```rust
#[get("/urls/{id}")] // Route attribute
async fn get_url_by_id(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    // ...
}
```

---

## 13. Async/Await

Both languages now have async/await, but with different models.

### C++ Coroutines (C++20)

```cpp
#include <coroutine>

std::future<HttpResponse> handle_request(Request req) {
    auto data = co_await fetch_data(req.id);
    co_return HttpResponse::ok(data);
}
```

### Rust Async (from `handlers/urls.rs`)

```rust
#[post("/shorten")]
async fn create_short_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    body: web::Json<CreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    let url = services::create_url(&pool, &body, config.short_code_length, user.user_id)?;

    let response = CreateUrlResponse {
        short_code: url.short_code.clone(),
        short_url: format!("{}/{}", config.base_url, url.short_code),
        // ...
    };

    Ok(HttpResponse::Created().json(response))
}
```

### Key Differences

| Aspect | C++ Coroutines | Rust Async |
|---|---|---|
| Runtime | None built-in | Tokio, async-std, etc. |
| State machine | Compiler-generated | Compiler-generated |
| Cancellation | Manual | Drop = cancel |
| Syntax | `co_await`, `co_return` | `.await` |

### Main Function (from `main.rs`)

```rust
#[actix_web::main] // Macro sets up async runtime
async fn main() -> std::io::Result<()> {
    let pool = infra::db::init_pool(&config.database_url)?;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(handlers::configure_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
```

---

## 14. Testing

### C++ Testing (Google Test)

```cpp
#include <gtest/gtest.h>

TEST(ConfigTest, DefaultValues) {
    Config config;
    EXPECT_EQ(config.database_url(), "urls.db");
    EXPECT_EQ(config.port(), 8080);
}

class DatabaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        pool_ = create_test_pool();
    }
    DbPool pool_;
};

TEST_F(DatabaseTest, CreateUrl) {
    auto url = create_url(pool_, "https://example.com", "test");
    EXPECT_EQ(url.short_code, "test");
}
```

### Rust Testing — Unit Tests Live Beside Code

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.database_url, "urls.db");
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.short_code_length, 7);
    }
}
```

### Handler Integration Tests (from `handlers/mod.rs`)

```rust
async fn setup_test_app(pool: DbPool) -> impl actix_web::dev::Service<...> {
    let config = test_config();
    let cache = test_cache();

    test::init_service(
        App::new()
            .app_data(web::Data::new(pool))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(cache))
            .configure(configure_routes),
    )
    .await
}

#[actix_rt::test]
async fn test_create_url_requires_auth() {
    let pool = setup_test_pool();
    let app = setup_test_app(pool).await;

    let req = test::TestRequest::post()
        .uri("/api/shorten")
        .set_json(serde_json::json!({ "url": "https://example.com" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
```

### Test Attributes

```rust
#[test]                              // Basic test
#[test] #[should_panic]              // Expected to panic
#[test] #[should_panic(expected = "msg")]
#[ignore]                            // Skip unless --include-ignored
#[actix_rt::test]                    // Async test (Actix runtime)
#[tokio::test]                       // Async test (Tokio runtime)
```

### Running Tests

```bash
cargo test                 # Run all tests
cargo test test_name       # Run specific test
cargo test --release       # Run in release mode
cargo test -- --nocapture  # Show println! output
```

---

## 15. Concurrency & Thread Safety

*New section — covers `r2d2`, the `Send`/`Sync` traits, and `moka` lock-free caching as used in this project.*

### The `Send` and `Sync` Marker Traits

C++ has no compile-time concept of "thread-safe." You wrap things in `std::mutex` and hope your team uses them correctly. Rust elevates thread-safety to the type system via two auto-traits:

- **`Send`** — values of this type can be transferred *to* another thread.
- **`Sync`** — `&T` can be shared *between* threads (i.e., `T` is safe under concurrent reads).

Most types are `Send + Sync` automatically. `Rc<T>` is neither (use `Arc<T>` across threads). `RefCell<T>` is `Send` but not `Sync` (use `Mutex<T>` or `RwLock<T>`).

### Connection Pooling with `r2d2` (from `infra/db.rs`)

```rust
pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_pool(database_url: &str) -> Result<DbPool, AppError> {
    let manager = SqliteConnectionManager::file(database_url)
        .with_init(|conn| {
            conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
        });
    Pool::builder().build(manager).map_err(/* ... */)
}
```

`Pool<SqliteConnectionManager>` is `Clone + Send + Sync`. Cloning is cheap (it's an `Arc` internally). Each handler gets a `web::Data<DbPool>` and calls `pool.get()` to check out a connection.

**C++ equivalent**: a `std::shared_ptr<ConnectionPool>` with internal `std::mutex` — but you'd write the synchronization yourself, and there's no compile-time check that you didn't forget to lock.

### Lock-Free Caching with `moka` (from `infra/cache.rs`)

```rust
use moka::sync::Cache;

#[derive(Clone)]
pub struct AppCache {
    pub urls: Cache<String, CachedUrl>,
    pub api_keys: Cache<String, CachedApiKey>,
}

impl AppCache {
    pub fn get_url(&self, code: &str) -> Option<CachedUrl> {
        self.urls.get(code)
    }

    pub fn insert_url(&self, code: &str, url: CachedUrl) {
        self.urls.insert(code.to_string(), url);
    }
}
```

`moka::sync::Cache` is concurrent, lock-free, with TTL support. No `Mutex` in sight. The whole thing is `Send + Sync`, so it lives in `web::Data<AppCache>` and is shared across all worker threads safely.

**C++ equivalent**: roll your own with `std::unordered_map` + `std::shared_mutex` + a TTL eviction thread. Or pull in TBB / folly. Either way, more code and more chances to get it wrong.

### `Arc<T>` vs `web::Data<T>`

| Usage | What it does |
|---|---|
| `Arc<T>` | Reference-counted shared ownership across threads. Like `std::shared_ptr<T>` for `Send + Sync` types. |
| `web::Data<T>` | Actix-web's wrapper. Internally an `Arc<T>`, but extracted from the framework's app state. |

```rust
HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(pool.clone()))   // Cheap clone — internal Arc
        .app_data(web::Data::new(cache.clone()))  // Same
        .configure(handlers::configure_routes)
})
```

### The Compile-Time Guarantee

If you accidentally try to share a non-`Sync` type between threads, the compiler refuses to build. There is no runtime "race condition" to discover in production — the bug doesn't compile.

---

## 16. Custom Extractors and the `FromRequest` Trait

*New section — Actix-web's request-guard pattern, used for `AuthenticatedUser`.*

In C++ web frameworks (like Crow or cpp-httplib), you typically read auth headers manually inside each handler. In Actix, you write a single type that implements `FromRequest`, and any handler that includes it as a parameter automatically gets authenticated requests pre-validated.

### The Auth Extractor (from `auth.rs`)

```rust
pub struct AuthenticatedUser {
    pub user_id: i64,
    pub api_key_id: i64,
}

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // Pull X-API-Key or "Authorization: Bearer <key>"
        let api_key = match extract_api_key(req) {
            Some(k) => k,
            None => return ready(Err(AppError::ValidationError("Missing API key".into()))),
        };

        let pool = req.app_data::<web::Data<DbPool>>().unwrap();
        let cache = req.app_data::<web::Data<AppCache>>().map(|d| d.as_ref());

        match services::validate_api_key_with_cache(pool, cache, &api_key) {
            Ok((user_id, api_key_id)) => ready(Ok(AuthenticatedUser { user_id, api_key_id })),
            Err(e) => ready(Err(e)),
        }
    }
}
```

### Usage — The Handler Doesn't See the Mechanics

```rust
#[get("/urls")]
async fn list_urls(
    user: AuthenticatedUser,        // ← extractor runs before this handler
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    query: web::Query<ListUrlsQuery>,
) -> Result<HttpResponse, AppError> {
    let urls = services::list_urls(&pool, user.user_id, &query)?;
    // ...
}
```

If the API key is missing or invalid, the request is rejected with the appropriate status before the handler body ever runs. No `if (!user) return 401;` boilerplate at the top of every handler.

### C++ Comparison

The closest analogue is a middleware decorator pattern, but most C++ HTTP frameworks make you either:
- Wrap the handler in a function template, or
- Read the header inline in every handler

Rust's trait-based extractor is statically dispatched (zero overhead) and composable: a handler can take *multiple* extractors (`user`, `pool`, `config`, `body`, `query`) and the framework wires them all up at compile time.

---

## 17. Const-Driven Validation with Attribute Macros

*New section — using `infra::constants` with the `validator` crate.*

This project centralizes magic numbers in `infra/constants.rs` and feeds them into `validator` derive attributes. It's a pattern that mixes Rust's strong type system with proc-macro metaprogramming in a way C++ has no real equivalent for.

### The Constants (`infra/constants.rs`)

```rust
/// Maximum allowed URL length in characters.
/// Typed `u64` because the validator crate's length(min/max = ..) attributes
/// require `u64` — using `usize` here would fail to compile.
pub const MAX_URL_LENGTH: u64 = 2048;
pub const MIN_CUSTOM_CODE_LENGTH: u64 = 3;
pub const MAX_CUSTOM_CODE_LENGTH: u64 = 20;
pub const MAX_TAG_NAME_LENGTH: u64 = 50;
```

### Wiring Constants Through Derive Attributes

```rust
use crate::infra::constants::{MAX_URL_LENGTH, MIN_CUSTOM_CODE_LENGTH, MAX_CUSTOM_CODE_LENGTH};

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUrlRequest {
    #[validate(url(message = "Invalid URL format"))]
    #[validate(length(max = MAX_URL_LENGTH, message = "URL is too long"))]
    pub url: String,

    #[validate(length(min = MIN_CUSTOM_CODE_LENGTH, max = MAX_CUSTOM_CODE_LENGTH))]
    pub custom_code: Option<String>,
}
```

The validator crate's proc macro reads these consts at compile time and bakes them into the generated `Validate::validate()` implementation. If you change `MAX_URL_LENGTH`, every derive picks up the new value with no manual edits.

### Why `u64`, not `usize`?

This is a real gotcha worth remembering: the `length(min = .., max = ..)` proc macro accepts *path expressions* — but it requires the path to evaluate to `u64`. If you write `pub const MAX_URL_LENGTH: usize = 2048;`, the project compiles right up to the point where the derive macro is expanded, then explodes with an unhelpful type-mismatch error.

For most other contexts, `usize` would be the natural choice (it's how Rust talks about array indices and lengths). Validator is the exception.

### C++ Comparison

In C++ you'd use `constexpr`:

```cpp
constexpr size_t MAX_URL_LENGTH = 2048;

class CreateUrlRequest {
    bool validate() const {
        if (url.size() > MAX_URL_LENGTH) return false;
        // ... manually code each check
    }
};
```

The validation logic is hand-written. Rust's macro generates it from the type definition.

---

## 18. Avoiding N+1 Queries with `HashMap`

*New section — the optimization pattern in `services::tags::get_urls_by_tag_with_tags`.*

A classic ORM trap: fetch a list of N parent rows, then fetch each parent's children in a separate query → N+1 queries. This project's tag lookup does it in 2 queries plus a `HashMap` join in memory.

### The Pattern

```rust
pub fn get_urls_by_tag_with_tags(
    pool: &DbPool,
    tag_id: i64,
    user_id: i64,
    query: &ListUrlsQuery,
) -> Result<Vec<(Url, Vec<Tag>)>, AppError> {
    let conn = get_conn(pool)?;

    // Query 1: paginated URLs for this tag
    let urls: Vec<Url> = stmt
        .query_map(params![tag_id, user_id, limit, offset], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    if urls.is_empty() {
        return Ok(vec![]);
    }

    // Query 2: ALL tags for this user's URLs (one trip to the DB)
    let mut url_tags_map: HashMap<i64, Vec<Tag>> = HashMap::new();

    let tag_rows = tag_stmt.query_map(params![user_id], |row| {
        Ok((row.get::<_, i64>(0)?, Tag { /* ... */ }))
    })?;

    for result in tag_rows {
        let (url_id, tag) = result?;
        url_tags_map.entry(url_id).or_default().push(tag);
    }

    // Stitch URLs with their tags in memory
    let result: Vec<(Url, Vec<Tag>)> = urls
        .into_iter()
        .map(|url| {
            let tags = url_tags_map.remove(&url.id).unwrap_or_default();
            (url, tags)
        })
        .collect();

    Ok(result)
}
```

### Why `entry(...).or_default().push(...)`?

This is the idiomatic Rust pattern for "append to a `Vec` keyed in a `HashMap`, creating the `Vec` if it doesn't exist."

- `entry(url_id)` returns an `Entry` enum (`Occupied` or `Vacant`).
- `.or_default()` either returns `&mut Vec<Tag>` for the existing entry or inserts a `Vec::default()` (empty) and returns a mutable reference.
- `.push(tag)` then appends.

**C++ equivalent:**

```cpp
url_tags_map[url_id].push_back(tag); // operator[] auto-inserts default
```

Rust forces the verbose path because mutable references through `HashMap` need explicit borrow tracking — but the result is the same shape, with a clearer ownership story.

### Why `.remove(&url.id)` Instead of `.get(&url.id)`?

`remove` returns the owned `Vec<Tag>` and takes it out of the map. We're consuming the map anyway, so this avoids cloning the inner vector. C++ would phrase this as "moving from the map's value."

---

## 19. Pagination: `count + list` Split

*New section — the pattern used across all list endpoints.*

A pagination response has two pieces of information: the page itself, and the total count so the client can compute `total_pages`. They're computed by separate SQL queries; both go through services that pair naturally:

### The Service Pair (`services/urls.rs`)

```rust
pub fn list_urls(pool: &DbPool, user_id: i64, query: &ListUrlsQuery) -> Result<Vec<Url>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
    let offset = (page - 1) * limit;
    let sort_order = match query.sort.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    let sql = Urls::list_by_user_with_order(sort_order);
    let mut stmt = conn.prepare(&sql)?;
    stmt.query_map(params![user_id, limit, offset], map_url_row)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

pub fn count_urls(pool: &DbPool, user_id: i64) -> Result<usize, AppError> {
    let count: i64 = conn.query_row(Urls::COUNT_BY_USER, params![user_id], |row| row.get(0))?;
    Ok(count as usize)
}
```

### The Handler Stitches Them

```rust
#[get("/urls")]
async fn list_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    query: web::Query<ListUrlsQuery>,
) -> Result<HttpResponse, AppError> {
    let urls = services::list_urls(&pool, user.user_id, &query)?;
    let total = services::count_urls(&pool, user.user_id)?;

    let url_responses: Vec<UrlResponse> = urls
        .into_iter()
        .map(|u| UrlResponse::from_url(u, &config.base_url))
        .collect();

    Ok(HttpResponse::Ok().json(UrlListResponse { total, urls: url_responses }))
}
```

### Why Not Combine Into One Query?

A single query with `COUNT(*) OVER ()` works but pays the count cost on every page fetch — including pages where the client doesn't care. Splitting them keeps each query simple, lets the planner choose the best index for each, and matches the natural shape of the response.

### Reusing `ListUrlsQuery` Across Endpoints

The same `ListUrlsQuery` (page, limit, sort) is used by `/api/urls`, `/api/tags/{id}/urls`, and any future paginated list. C++ would tend to hand-roll a query-string parser per route; Rust's `web::Query<T>` deserializes any `T: Deserialize` automatically.

---

## 20. Common Gotchas for C++ Programmers

### 1. Move is the Default, Not Copy

```rust
let s1 = String::from("hello");
let s2 = s1; // s1 is MOVED, not copied!
// println!("{}", s1); // ERROR: s1 is no longer valid

// To copy, explicitly clone:
let s1 = String::from("hello");
let s2 = s1.clone();
println!("{}", s1); // OK
```

### 2. No Null Pointers

```rust
// This doesn't exist in safe Rust:
// let ptr: *const i32 = std::ptr::null();

// Use Option instead:
let maybe_value: Option<i32> = None;
```

### 3. No Implicit Conversions

```rust
let x: i32 = 5;
// let y: i64 = x;       // ERROR: no implicit conversion
let y: i64 = x as i64;   // OK: explicit cast
let y: i64 = x.into();   // OK: if From trait is implemented
```

### 4. Mutable Bindings, Not Mutable Types

```rust
let x = 5;     // Immutable binding
// x = 6;      // ERROR

let mut x = 5; // Mutable binding
x = 6;         // OK
```

### 5. No Uninitialized Variables

```rust
let x: i32;
// println!("{}", x); // ERROR: use of uninitialized variable

let x: i32;
if condition {
    x = 1;
} else {
    x = 2;
}
println!("{}", x); // OK: compiler proves all paths initialize x
```

### 6. Lifetimes When Returning References

```rust
// ERROR: returns reference to local data
// fn bad() -> &str {
//     let s = String::from("hello");
//     &s // s is dropped here!
// }

// OK: return owned data
fn good() -> String {
    String::from("hello")
}

// OK: borrow from input
fn also_good(s: &str) -> &str {
    &s[0..3]
}
```

### 7. Semicolons Matter

```rust
fn add(a: i32, b: i32) -> i32 {
    a + b // No semicolon = return value (expression)
}

fn add_wrong(a: i32, b: i32) -> i32 {
    a + b; // Semicolon = statement, returns ()
    // ERROR: expected i32, found ()
}
```

### 8. `match` Must Be Exhaustive

```rust
enum Color { Red, Green, Blue }

fn name(c: Color) -> &'static str {
    match c {
        Color::Red => "red",
        Color::Green => "green",
        // ERROR: non-exhaustive patterns: `Blue` not covered
    }
}
```

### 9. No Function Overloading

```rust
// Can't do this:
// fn process(x: i32) {}
// fn process(x: String) {} // ERROR: duplicate definition

// Use traits instead:
trait Process {
    fn process(&self);
}

impl Process for i32    { fn process(&self) { /* ... */ } }
impl Process for String { fn process(&self) { /* ... */ } }
```

### 10. Closures Capture by Reference by Default

```rust
let x = vec![1, 2, 3];
let closure = || println!("{:?}", x); // Borrows x
closure();
println!("{:?}", x); // OK: x is still valid

// To move:
let x = vec![1, 2, 3];
let closure = move || println!("{:?}", x); // Moves x
closure();
// println!("{:?}", x); // ERROR: x was moved
```

### 11. Validator `length(...)` Wants `u64`, Not `usize` *(new)*

This bites when wiring constants into derive attributes:

```rust
// ❌ Won't compile through #[derive(Validate)]
pub const MAX_URL_LENGTH: usize = 2048;

// ✅ Required by the validator crate's macros
pub const MAX_URL_LENGTH: u64 = 2048;
```

The error message points at the derive site, not the const, which makes it harder to track down on first encounter.

### 12. `?` Needs `From` to Cross Error Types *(new)*

`?` automatically converts the inner error via `From::from`. If there's no `impl From<SourceError> for YourError`, `?` won't compile. The fix is one trait impl per source error:

```rust
impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}
// Now `let conn = pool.get()?;` works inside any function returning Result<_, AppError>
```

### 13. SQLite `datetime('now')` Has 1-Second Resolution *(new — project-specific)*

Tests that assert `updated_at` changes after a quick `update_url(...)` call sometimes flake because both timestamps round to the same second. The fix is to explicitly insert dated rows in tests, or `std::thread::sleep(Duration::from_millis(1100))` between the two writes.

### 14. `match` on `&str` Categories Without `.as_str()` *(new — `woothee` crate quirk)*

`woothee::parser::Parser::parse(...).result.category` returns a `&str`. You match it directly, not with `.as_str()` or `&*`:

```rust
let category = parser.parse(ua).map(|r| r.category).unwrap_or("unknown");
match category {
    "pc"     => "desktop",
    "mobile" => "mobile",
    "tablet" => "tablet",
    _        => "other",
}
```

---

## Quick Reference Card

### Syntax Comparison

| C++ | Rust |
|---|---|
| `int x = 5;` | `let x: i32 = 5;` |
| `const int x = 5;` | `let x = 5;` (immutable by default) |
| `int x = 5; x = 6;` | `let mut x = 5; x = 6;` |
| `int* ptr = &x;` | `let ptr = &x;` |
| `int& ref = x;` | `let r = &x;` |
| `std::vector<int>` | `Vec<i32>` |
| `std::unordered_map<K,V>` | `HashMap<K, V>` |
| `std::optional<T>` | `Option<T>` |
| `std::variant<A,B,C>` | `enum E { A, B, C }` |
| `nullptr` | `None` (for `Option`) |
| `throw Exception()` | `return Err(e)` |
| `try { } catch { }` | `match result { Ok/Err }` |
| `auto x = ...` | `let x = ...` |
| `for (auto& x : vec)` | `for x in &vec` |
| `[](int x) { return x*2; }` | `|x| x * 2` |
| `std::make_unique<T>()` | `Box::new(T)` |
| `std::make_shared<T>()` | `Rc::new(T)` or `Arc::new(T)` |
| `std::shared_mutex` | `RwLock<T>` |
| `std::mutex` | `Mutex<T>` |
| `std::atomic<T>` | `AtomicI32`, `AtomicUsize`, etc. |
| (manual thread-safety) | `Send + Sync` marker traits |

---

*Document generated from the url-shortener project analysis. Sections 15–19 added 2026-05-07 covering concurrency primitives, custom extractors, const-driven validation, N+1 avoidance, and pagination patterns introduced after the original document.*
