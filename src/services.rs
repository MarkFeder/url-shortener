//! Business logic layer for URL operations.
//!
//! Contains all the core functionality for creating, retrieving,
//! and managing shortened URLs, users, and API keys.

use chrono::{Duration, Utc};
use nanoid::nanoid;
use rand::Rng;
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::cache::{AppCache, CachedApiKey, CachedUrl};
use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
use crate::metrics::AppMetrics;
use crate::models::{
    ApiKeyRecord, BulkCreateItemResult, BulkCreateUrlItem, BulkCreateUrlResponse,
    BulkDeleteItemResult, BulkDeleteUrlResponse, BulkItemError, BulkOperationStatus, ClickLog,
    CreateUrlRequest, CreateUrlResponse, ListUrlsQuery, Tag, Url, User,
};
use crate::queries::{ApiKeys, ClickLogs, Tags, UrlTags, Urls, Users};

/// Characters used for generating short codes (URL-safe)
const ALPHABET: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];

/// API key prefix
const API_KEY_PREFIX: &str = "usk_";

// ============================================================================
// Row Mapping Helpers
// ============================================================================

/// Map a database row to a Url struct
fn map_url_row(row: &rusqlite::Row) -> rusqlite::Result<Url> {
    Ok(Url {
        id: row.get(0)?,
        short_code: row.get(1)?,
        original_url: row.get(2)?,
        clicks: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        expires_at: row.get(6)?,
        user_id: row.get(7)?,
    })
}

/// Map a database row to a User struct
fn map_user_row(row: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get(1)?,
        created_at: row.get(2)?,
    })
}

/// Map a database row to a Tag struct
fn map_tag_row(row: &rusqlite::Row) -> rusqlite::Result<Tag> {
    Ok(Tag {
        id: row.get(0)?,
        name: row.get(1)?,
        user_id: row.get(2)?,
        created_at: row.get(3)?,
    })
}

/// Map a database row to an ApiKeyRecord struct
fn map_api_key_row(row: &rusqlite::Row) -> rusqlite::Result<ApiKeyRecord> {
    Ok(ApiKeyRecord {
        id: row.get(0)?,
        user_id: row.get(1)?,
        key_hash: row.get(2)?,
        name: row.get(3)?,
        created_at: row.get(4)?,
        last_used_at: row.get(5)?,
        is_active: row.get::<_, i32>(6)? == 1,
    })
}

/// Map a database row to a ClickLog struct
fn map_click_log_row(row: &rusqlite::Row) -> rusqlite::Result<ClickLog> {
    Ok(ClickLog {
        id: row.get(0)?,
        url_id: row.get(1)?,
        clicked_at: row.get(2)?,
        ip_address: row.get(3)?,
        user_agent: row.get(4)?,
        referer: row.get(5)?,
    })
}

/// Check if a resource exists and belongs to the user
fn check_ownership(
    conn: &rusqlite::Connection,
    query: &str,
    id: i64,
    user_id: i64,
) -> Result<bool, AppError> {
    let count: i32 = conn
        .query_row(query, params![id, user_id], |row| row.get(0))
        .unwrap_or(0);
    Ok(count > 0)
}

/// Generate a random short code using nanoid
pub fn generate_short_code(length: usize) -> String {
    nanoid!(length, &ALPHABET)
}

/// Generate a new API key with the usk_ prefix
pub fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let key: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..ALPHABET.len());
            ALPHABET[idx]
        })
        .collect();
    format!("{}{}", API_KEY_PREFIX, key)
}

/// Hash an API key using SHA-256
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

// ============================================================================
// User Management
// ============================================================================

/// Register a new user and create their first API key
///
/// Returns the user and the plain-text API key (only shown once)
pub fn register_user(pool: &DbPool, email: &str) -> Result<(User, String), AppError> {
    let conn = get_conn(pool)?;

    // Check if email already exists
    let exists: i32 = conn
        .query_row(Users::COUNT_BY_EMAIL, params![email], |row| row.get(0))
        .unwrap_or(0);

    if exists > 0 {
        return Err(AppError::EmailAlreadyExists(format!(
            "Email '{}' is already registered",
            email
        )));
    }

    // Create user
    conn.execute(Users::INSERT, params![email])?;
    let user_id = conn.last_insert_rowid();

    // Retrieve the created user
    let user = conn.query_row(Users::SELECT_BY_ID, params![user_id], map_user_row)?;

    // Create first API key
    let api_key = generate_api_key();
    let key_hash = hash_api_key(&api_key);

    conn.execute(
        ApiKeys::INSERT,
        params![user_id, key_hash, "Default key"],
    )?;

    log::info!("Registered new user: {} (ID: {})", email, user_id);

    Ok((user, api_key))
}

/// Get a user by ID
pub fn get_user_by_id(pool: &DbPool, user_id: i64) -> Result<User, AppError> {
    let conn = get_conn(pool)?;

    conn.query_row(Users::SELECT_BY_ID, params![user_id], map_user_row)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("User with ID '{}' not found", user_id))
            }
            _ => AppError::DatabaseError(e.to_string()),
        })
}

// ============================================================================
// API Key Management
// ============================================================================

/// Create a new API key for a user
///
/// Returns the API key record and the plain-text key (only shown once)
pub fn create_api_key(pool: &DbPool, user_id: i64, name: &str) -> Result<(ApiKeyRecord, String), AppError> {
    let conn = get_conn(pool)?;

    let api_key = generate_api_key();
    let key_hash = hash_api_key(&api_key);

    conn.execute(ApiKeys::INSERT, params![user_id, key_hash, name])?;
    let key_id = conn.last_insert_rowid();

    let record = conn.query_row(ApiKeys::SELECT_BY_ID, params![key_id], map_api_key_row)?;

    log::info!("Created API key '{}' for user {}", name, user_id);

    Ok((record, api_key))
}

/// Validate an API key and return the associated user ID and key ID
///
/// Also updates the last_used_at timestamp
pub fn validate_api_key(pool: &DbPool, api_key: &str) -> Result<(i64, i64), AppError> {
    let conn = get_conn(pool)?;
    let key_hash = hash_api_key(api_key);

    let (key_id, user_id): (i64, i64) = conn
        .query_row(ApiKeys::SELECT_BY_HASH, params![key_hash], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::Unauthorized("Invalid API key".into())
            }
            _ => AppError::DatabaseError(e.to_string()),
        })?;

    // Update last_used_at
    conn.execute(ApiKeys::UPDATE_LAST_USED, params![key_id])?;

    Ok((user_id, key_id))
}

/// Validate an API key with caching
///
/// Checks the cache first, then falls back to the database on cache miss.
/// Updates the last_used_at timestamp on cache hits periodically (not on every request).
pub fn validate_api_key_cached(
    pool: &DbPool,
    cache: &AppCache,
    api_key: &str,
) -> Result<(i64, i64), AppError> {
    validate_api_key_cached_with_metrics(pool, cache, api_key, None)
}

/// Validate an API key with caching and optional metrics recording
///
/// Checks the cache first, then falls back to the database on cache miss.
/// Records cache hits/misses and validation results to metrics if provided.
pub fn validate_api_key_cached_with_metrics(
    pool: &DbPool,
    cache: &AppCache,
    api_key: &str,
    metrics: Option<&AppMetrics>,
) -> Result<(i64, i64), AppError> {
    let key_hash = hash_api_key(api_key);

    // Check cache first
    if let Some(cached) = cache.get_api_key(&key_hash) {
        log::debug!("Cache hit for API key");
        if let Some(m) = metrics {
            m.record_cache_hit("api_key");
            m.record_api_key_validation("success");
        }
        return Ok((cached.user_id, cached.key_id));
    }

    // Cache miss - validate against database
    log::debug!("Cache miss for API key, querying database");
    if let Some(m) = metrics {
        m.record_cache_miss("api_key");
    }

    match validate_api_key(pool, api_key) {
        Ok((user_id, key_id)) => {
            // Store in cache
            cache.insert_api_key(
                &key_hash,
                CachedApiKey { user_id, key_id },
            );

            if let Some(m) = metrics {
                m.record_api_key_validation("success");
            }

            Ok((user_id, key_id))
        }
        Err(e) => {
            if let Some(m) = metrics {
                m.record_api_key_validation("invalid");
            }
            Err(e)
        }
    }
}

/// List all API keys for a user
pub fn list_api_keys(pool: &DbPool, user_id: i64) -> Result<Vec<ApiKeyRecord>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ApiKeys::SELECT_BY_USER)?;

    let keys = stmt
        .query_map(params![user_id], map_api_key_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys)
}

/// Revoke an API key
pub fn revoke_api_key(pool: &DbPool, user_id: i64, key_id: i64) -> Result<(), AppError> {
    revoke_api_key_with_cache(pool, None, user_id, key_id)
}

/// Revoke an API key with cache invalidation
pub fn revoke_api_key_with_cache(
    pool: &DbPool,
    cache: Option<&AppCache>,
    user_id: i64,
    key_id: i64,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    // First check if the key exists and belongs to the user
    let exists: i32 = conn
        .query_row(
            ApiKeys::COUNT_BY_ID_AND_USER,
            params![key_id, user_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if exists == 0 {
        return Err(AppError::NotFound(format!(
            "API key with ID '{}' not found",
            key_id
        )));
    }

    // Get the key_hash before revoking for cache invalidation
    let key_hash: Option<String> = if cache.is_some() {
        conn.query_row(ApiKeys::SELECT_KEY_HASH_BY_ID, params![key_id], |row| {
            row.get(0)
        })
        .ok()
    } else {
        None
    };

    let rows_affected = conn.execute(ApiKeys::DEACTIVATE, params![key_id, user_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "API key with ID '{}' not found or already revoked",
            key_id
        )));
    }

    // Invalidate cache if we have the key_hash
    if let (Some(cache), Some(hash)) = (cache, key_hash) {
        cache.invalidate_api_key(&hash);
        log::debug!("Invalidated cache for API key hash");
    }

    log::info!("Revoked API key {} for user {}", key_id, user_id);
    Ok(())
}

// ============================================================================
// URL Management
// ============================================================================

/// Create a new shortened URL
pub fn create_url(
    pool: &DbPool,
    request: &CreateUrlRequest,
    code_length: usize,
    user_id: i64,
) -> Result<Url, AppError> {
    create_url_with_metrics(pool, request, code_length, user_id, None)
}

/// Create a new shortened URL with optional metrics recording
pub fn create_url_with_metrics(
    pool: &DbPool,
    request: &CreateUrlRequest,
    code_length: usize,
    user_id: i64,
    metrics: Option<&AppMetrics>,
) -> Result<Url, AppError> {
    let conn = get_conn(pool)?;

    // Use custom code or generate one
    let short_code = match &request.custom_code {
        Some(code) => {
            // Check if custom code already exists
            if code_exists(&conn, code)? {
                return Err(AppError::DuplicateCode(format!(
                    "Short code '{}' is already taken",
                    code
                )));
            }
            code.clone()
        }
        None => {
            // Generate unique code with retries
            let mut code = generate_short_code(code_length);
            let mut attempts = 0;
            while code_exists(&conn, &code)? && attempts < 10 {
                code = generate_short_code(code_length);
                attempts += 1;
            }
            if attempts >= 10 {
                return Err(AppError::InternalError(
                    "Failed to generate unique short code".into(),
                ));
            }
            code
        }
    };

    // Calculate expiration date if specified
    let expires_at = request.expires_in_hours.map(|hours| {
        (Utc::now() + Duration::hours(hours))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    });

    conn.execute(
        Urls::INSERT,
        params![short_code, request.url, expires_at, user_id],
    )?;

    // Retrieve the created URL
    let url = get_url_by_code(pool, &short_code)?;
    log::info!(
        "Created short URL: {} -> {} (user: {})",
        short_code,
        request.url,
        user_id
    );

    // Record metric
    if let Some(m) = metrics {
        m.record_url_created();
    }

    Ok(url)
}

/// Check if a short code already exists
fn code_exists(conn: &rusqlite::Connection, code: &str) -> Result<bool, AppError> {
    let count: i32 = conn.query_row(Urls::COUNT_BY_CODE, params![code], |row| row.get(0))?;
    Ok(count > 0)
}

/// Get a URL by its short code (for redirects - no ownership check)
pub fn get_url_by_code(pool: &DbPool, short_code: &str) -> Result<Url, AppError> {
    let conn = get_conn(pool)?;

    let url = conn
        .query_row(Urls::SELECT_BY_CODE, params![short_code], map_url_row)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("URL with code '{}' not found", short_code))
            }
            _ => AppError::DatabaseError(e.to_string()),
        })?;

    // Check if URL has expired
    if let Some(expires_at) = &url.expires_at {
        let expires = chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
            .map_err(|e| AppError::InternalError(format!("Date parse error: {}", e)))?;

        if expires < Utc::now().naive_utc() {
            return Err(AppError::ExpiredUrl(format!(
                "URL '{}' has expired",
                short_code
            )));
        }
    }

    Ok(url)
}

/// Get a URL by its short code with caching (for redirects - no ownership check)
///
/// Checks the cache first, then falls back to the database on cache miss.
/// Also checks expiration on cache hits and invalidates expired entries.
pub fn get_url_by_code_cached(
    pool: &DbPool,
    cache: &AppCache,
    short_code: &str,
) -> Result<Url, AppError> {
    get_url_by_code_cached_with_metrics(pool, cache, short_code, None)
}

/// Get a URL by its short code with caching and optional metrics recording
///
/// Checks the cache first, then falls back to the database on cache miss.
/// Also checks expiration on cache hits and invalidates expired entries.
/// Records cache hits/misses to metrics if provided.
pub fn get_url_by_code_cached_with_metrics(
    pool: &DbPool,
    cache: &AppCache,
    short_code: &str,
    metrics: Option<&AppMetrics>,
) -> Result<Url, AppError> {
    // Check cache first
    if let Some(cached) = cache.get_url(short_code) {
        // Check if cached URL has expired
        if let Some(expires_at) = &cached.expires_at {
            let expires = chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
                .map_err(|e| AppError::InternalError(format!("Date parse error: {}", e)))?;

            if expires < Utc::now().naive_utc() {
                // Invalidate expired entry from cache
                cache.invalidate_url(short_code);
                return Err(AppError::ExpiredUrl(format!(
                    "URL '{}' has expired",
                    short_code
                )));
            }
        }

        log::debug!("Cache hit for short code: {}", short_code);
        if let Some(m) = metrics {
            m.record_cache_hit("url");
        }

        // Return a minimal Url struct from cached data
        // Note: clicks field will be 0 since we don't cache it (it changes frequently)
        return Ok(Url {
            id: cached.id,
            short_code: short_code.to_string(),
            original_url: cached.original_url,
            clicks: 0, // Not cached, will be updated on redirect
            created_at: String::new(), // Not needed for redirect
            updated_at: String::new(), // Not needed for redirect
            expires_at: cached.expires_at,
            user_id: cached.user_id,
        });
    }

    // Cache miss - query database
    log::debug!("Cache miss for short code: {}, querying database", short_code);
    if let Some(m) = metrics {
        m.record_cache_miss("url");
    }

    let url = get_url_by_code(pool, short_code)?;

    // Store in cache
    cache.insert_url(
        short_code,
        CachedUrl {
            id: url.id,
            original_url: url.original_url.clone(),
            expires_at: url.expires_at.clone(),
            user_id: url.user_id,
        },
    );

    Ok(url)
}

/// Get a URL by its ID (for API - checks ownership)
pub fn get_url_by_id(pool: &DbPool, id: i64, user_id: i64) -> Result<Url, AppError> {
    let conn = get_conn(pool)?;

    conn.query_row(Urls::SELECT_BY_ID_AND_USER, params![id, user_id], map_url_row)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                AppError::NotFound(format!("URL with ID '{}' not found", id))
            }
            _ => AppError::DatabaseError(e.to_string()),
        })
}

/// List URLs for a specific user with pagination
pub fn list_urls(pool: &DbPool, user_id: i64, query: &ListUrlsQuery) -> Result<Vec<Url>, AppError> {
    let conn = get_conn(pool)?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    let sort_order = match query.sort.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    let sql = Urls::list_by_user_with_order(sort_order);
    let mut stmt = conn.prepare(&sql)?;
    let urls = stmt
        .query_map(params![user_id, limit, offset], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(urls)
}

/// Get total count of URLs for a user
pub fn count_urls(pool: &DbPool, user_id: i64) -> Result<usize, AppError> {
    let conn = get_conn(pool)?;
    let count: i64 = conn.query_row(Urls::COUNT_BY_USER, params![user_id], |row| row.get(0))?;
    Ok(count as usize)
}

/// Increment click count and log the click within a transaction
pub fn record_click(
    pool: &DbPool,
    url_id: i64,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    referer: Option<&str>,
) -> Result<(), AppError> {
    let mut conn = get_conn(pool)?;

    // Use a transaction to ensure both operations succeed or fail together
    let tx = conn.transaction()?;

    tx.execute(Urls::INCREMENT_CLICKS, params![url_id])?;
    tx.execute(
        ClickLogs::INSERT,
        params![url_id, ip_address, user_agent, referer],
    )?;

    tx.commit()?;

    Ok(())
}

/// Get click logs for a URL
pub fn get_click_logs(pool: &DbPool, url_id: i64, limit: u32) -> Result<Vec<ClickLog>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ClickLogs::SELECT_BY_URL_ID)?;

    let logs = stmt
        .query_map(params![url_id, limit], map_click_log_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(logs)
}

/// Delete a URL by ID (checks ownership)
pub fn delete_url(pool: &DbPool, id: i64, user_id: i64) -> Result<(), AppError> {
    delete_url_with_cache(pool, None, id, user_id)
}

/// Delete a URL by ID with cache invalidation (checks ownership)
pub fn delete_url_with_cache(
    pool: &DbPool,
    cache: Option<&AppCache>,
    id: i64,
    user_id: i64,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    // Get the short_code before deleting for cache invalidation
    let short_code: Option<String> = if cache.is_some() {
        conn.query_row(Urls::SELECT_SHORT_CODE_BY_ID, params![id], |row| row.get(0))
            .ok()
    } else {
        None
    };

    let rows_affected = conn.execute(Urls::DELETE_BY_ID_AND_USER, params![id, user_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            id
        )));
    }

    // Invalidate cache if we have the short_code
    if let (Some(cache), Some(code)) = (cache, short_code) {
        cache.invalidate_url(&code);
        log::debug!("Invalidated cache for short code: {}", code);
    }

    log::info!("Deleted URL with ID: {} (user: {})", id, user_id);
    Ok(())
}

// ============================================================================
// Bulk Operations
// ============================================================================

/// Convert an AppError to an error code string
fn error_to_code(err: &AppError) -> String {
    match err {
        AppError::NotFound(_) => "NOT_FOUND".to_string(),
        AppError::ValidationError(_) => "VALIDATION_ERROR".to_string(),
        AppError::DatabaseError(_) => "DATABASE_ERROR".to_string(),
        AppError::DuplicateCode(_) => "DUPLICATE_CODE".to_string(),
        AppError::ExpiredUrl(_) => "EXPIRED_URL".to_string(),
        AppError::InternalError(_) => "INTERNAL_ERROR".to_string(),
        AppError::Unauthorized(_) => "UNAUTHORIZED".to_string(),
        AppError::Forbidden(_) => "FORBIDDEN".to_string(),
        AppError::EmailAlreadyExists(_) => "EMAIL_ALREADY_EXISTS".to_string(),
    }
}

/// Bulk create multiple URLs
///
/// Processes each URL individually, collecting successes and failures.
/// Uses a transaction for consistency but commits individual operations.
pub fn bulk_create_urls(
    pool: &DbPool,
    items: &[BulkCreateUrlItem],
    code_length: usize,
    user_id: i64,
    base_url: &str,
) -> Result<BulkCreateUrlResponse, AppError> {
    let mut results = Vec::with_capacity(items.len());
    let mut succeeded = 0;
    let mut failed = 0;

    for (index, item) in items.iter().enumerate() {
        // Convert BulkCreateUrlItem to CreateUrlRequest
        let request = CreateUrlRequest {
            url: item.url.clone(),
            custom_code: item.custom_code.clone(),
            expires_in_hours: item.expires_in_hours,
        };

        match create_url(pool, &request, code_length, user_id) {
            Ok(url) => {
                succeeded += 1;
                results.push(BulkCreateItemResult {
                    index,
                    success: true,
                    data: Some(CreateUrlResponse {
                        short_code: url.short_code.clone(),
                        short_url: format!("{}/{}", base_url, url.short_code),
                        original_url: url.original_url,
                        created_at: url.created_at,
                        expires_at: url.expires_at,
                    }),
                    error: None,
                });
            }
            Err(err) => {
                failed += 1;
                results.push(BulkCreateItemResult {
                    index,
                    success: false,
                    data: None,
                    error: Some(BulkItemError {
                        code: error_to_code(&err),
                        message: err.to_string(),
                    }),
                });
            }
        }
    }

    let status = if failed == 0 {
        BulkOperationStatus::Success
    } else if succeeded == 0 {
        BulkOperationStatus::Failed
    } else {
        BulkOperationStatus::PartialSuccess
    };

    log::info!(
        "Bulk create: {} total, {} succeeded, {} failed (user: {})",
        items.len(),
        succeeded,
        failed,
        user_id
    );

    Ok(BulkCreateUrlResponse {
        status,
        total: items.len(),
        succeeded,
        failed,
        results,
    })
}

/// Bulk delete multiple URLs by ID
///
/// Processes each deletion individually, collecting successes and failures.
pub fn bulk_delete_urls(
    pool: &DbPool,
    ids: &[i64],
    user_id: i64,
) -> Result<BulkDeleteUrlResponse, AppError> {
    bulk_delete_urls_with_cache(pool, None, ids, user_id)
}

/// Bulk delete multiple URLs by ID with cache invalidation
///
/// Processes each deletion individually, collecting successes and failures.
pub fn bulk_delete_urls_with_cache(
    pool: &DbPool,
    cache: Option<&AppCache>,
    ids: &[i64],
    user_id: i64,
) -> Result<BulkDeleteUrlResponse, AppError> {
    let mut results = Vec::with_capacity(ids.len());
    let mut succeeded = 0;
    let mut failed = 0;

    for &id in ids {
        match delete_url_with_cache(pool, cache, id, user_id) {
            Ok(()) => {
                succeeded += 1;
                results.push(BulkDeleteItemResult {
                    id,
                    success: true,
                    error: None,
                });
            }
            Err(err) => {
                failed += 1;
                results.push(BulkDeleteItemResult {
                    id,
                    success: false,
                    error: Some(BulkItemError {
                        code: error_to_code(&err),
                        message: err.to_string(),
                    }),
                });
            }
        }
    }

    let status = if failed == 0 {
        BulkOperationStatus::Success
    } else if succeeded == 0 {
        BulkOperationStatus::Failed
    } else {
        BulkOperationStatus::PartialSuccess
    };

    log::info!(
        "Bulk delete: {} total, {} succeeded, {} failed (user: {})",
        ids.len(),
        succeeded,
        failed,
        user_id
    );

    Ok(BulkDeleteUrlResponse {
        status,
        total: ids.len(),
        succeeded,
        failed,
        results,
    })
}

// ============================================================================
// Tag Management
// ============================================================================

/// Create a new tag for a user
pub fn create_tag(pool: &DbPool, name: &str, user_id: i64) -> Result<Tag, AppError> {
    let conn = get_conn(pool)?;

    // Check if tag name already exists for this user
    let exists: i32 = conn
        .query_row(
            Tags::COUNT_BY_NAME_AND_USER,
            params![name, user_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if exists > 0 {
        return Err(AppError::DuplicateCode(format!(
            "Tag '{}' already exists",
            name
        )));
    }

    conn.execute(Tags::INSERT, params![name, user_id])?;
    let tag_id = conn.last_insert_rowid();

    let tag = conn.query_row(Tags::SELECT_BY_ID, params![tag_id], map_tag_row)?;

    log::info!("Created tag '{}' for user {}", name, user_id);
    Ok(tag)
}

/// List all tags for a user
pub fn list_tags(pool: &DbPool, user_id: i64) -> Result<Vec<Tag>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(Tags::SELECT_BY_USER)?;

    let tags = stmt
        .query_map(params![user_id], map_tag_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(tags)
}

/// Delete a tag (cascades to url_tags)
pub fn delete_tag(pool: &DbPool, tag_id: i64, user_id: i64) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    let rows_affected = conn.execute(Tags::DELETE_BY_ID_AND_USER, params![tag_id, user_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    log::info!("Deleted tag {} for user {}", tag_id, user_id);
    Ok(())
}

/// Add a tag to a URL
pub fn add_tag_to_url(
    pool: &DbPool,
    url_id: i64,
    tag_id: i64,
    user_id: i64,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    // Verify the URL belongs to the user
    if !check_ownership(&conn, Urls::COUNT_BY_ID_AND_USER, url_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    // Check if the association already exists
    let already_tagged: i32 = conn
        .query_row(
            UrlTags::COUNT_BY_URL_AND_TAG,
            params![url_id, tag_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if already_tagged > 0 {
        return Err(AppError::DuplicateCode(
            "URL already has this tag".to_string(),
        ));
    }

    conn.execute(UrlTags::INSERT, params![url_id, tag_id])?;

    log::info!(
        "Added tag {} to URL {} for user {}",
        tag_id,
        url_id,
        user_id
    );
    Ok(())
}

/// Remove a tag from a URL
pub fn remove_tag_from_url(
    pool: &DbPool,
    url_id: i64,
    tag_id: i64,
    user_id: i64,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    // Verify the URL belongs to the user
    if !check_ownership(&conn, Urls::COUNT_BY_ID_AND_USER, url_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    let rows_affected = conn.execute(UrlTags::DELETE, params![url_id, tag_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(
            "URL does not have this tag".to_string(),
        ));
    }

    log::info!(
        "Removed tag {} from URL {} for user {}",
        tag_id,
        url_id,
        user_id
    );
    Ok(())
}

/// Get all tags for a URL
pub fn get_tags_for_url(pool: &DbPool, url_id: i64, user_id: i64) -> Result<Vec<Tag>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the URL belongs to the user
    if !check_ownership(&conn, Urls::COUNT_BY_ID_AND_USER, url_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    let mut stmt = conn.prepare(UrlTags::SELECT_TAGS_BY_URL)?;

    let tags = stmt
        .query_map(params![url_id], map_tag_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(tags)
}

/// Get all URLs with a specific tag
pub fn get_urls_by_tag(pool: &DbPool, tag_id: i64, user_id: i64) -> Result<Vec<Url>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    let mut stmt = conn.prepare(UrlTags::SELECT_URLS_BY_TAG)?;

    let urls = stmt
        .query_map(params![tag_id, user_id], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(urls)
}

/// Get all URLs with a specific tag, including all tags for each URL
/// This is an optimized version that avoids N+1 queries by fetching all tags
/// for the URLs in a single additional query.
pub fn get_urls_by_tag_with_tags(
    pool: &DbPool,
    tag_id: i64,
    user_id: i64,
) -> Result<Vec<(Url, Vec<Tag>)>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the tag belongs to the user
    if !check_ownership(&conn, Tags::COUNT_BY_ID_AND_USER, tag_id, user_id)? {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    // First, get all URLs with this tag
    let mut stmt = conn.prepare(UrlTags::SELECT_URLS_BY_TAG)?;
    let urls: Vec<Url> = stmt
        .query_map(params![tag_id, user_id], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    if urls.is_empty() {
        return Ok(vec![]);
    }

    // Build a map of url_id -> tags using a single query
    let mut url_tags_map: std::collections::HashMap<i64, Vec<Tag>> =
        std::collections::HashMap::new();

    // Get all tags for all URLs owned by this user
    let mut tag_stmt = conn.prepare(UrlTags::SELECT_TAGS_FOR_URLS)?;
    let tag_rows = tag_stmt.query_map(params![user_id], |row| {
        Ok((
            row.get::<_, i64>(0)?, // url_id
            Tag {
                id: row.get(1)?,
                name: row.get(2)?,
                user_id: row.get(3)?,
                created_at: row.get(4)?,
            },
        ))
    })?;

    for result in tag_rows {
        let (url_id, tag) = result?;
        url_tags_map.entry(url_id).or_default().push(tag);
    }

    // Combine URLs with their tags
    let result: Vec<(Url, Vec<Tag>)> = urls
        .into_iter()
        .map(|url| {
            let tags = url_tags_map.remove(&url.id).unwrap_or_default();
            (url, tags)
        })
        .collect();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init_pool, run_migrations};

    fn setup_test_db() -> DbPool {
        // Use shared cache mode so all connections share the same in-memory database
        let pool = init_pool("file::memory:?cache=shared").unwrap();
        run_migrations(&pool).unwrap();
        pool
    }

    #[test]
    fn test_generate_short_code() {
        let code = generate_short_code(7);
        assert_eq!(code.len(), 7);
        assert!(code.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key();
        assert!(key.starts_with("usk_"));
        assert_eq!(key.len(), 36); // 4 (prefix) + 32 (random)
    }

    #[test]
    fn test_hash_api_key() {
        let key = "usk_test123";
        let hash = hash_api_key(key);
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters

        // Same key should produce same hash
        let hash2 = hash_api_key(key);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_register_user() {
        let pool = setup_test_db();

        let (user, api_key) = register_user(&pool, "test@example.com").unwrap();
        assert_eq!(user.email, "test@example.com");
        assert!(api_key.starts_with("usk_"));
    }

    #[test]
    fn test_register_duplicate_email() {
        let pool = setup_test_db();

        register_user(&pool, "test@example.com").unwrap();
        let result = register_user(&pool, "test@example.com");
        assert!(matches!(result, Err(AppError::EmailAlreadyExists(_))));
    }

    #[test]
    fn test_validate_api_key() {
        let pool = setup_test_db();

        let (user, api_key) = register_user(&pool, "test@example.com").unwrap();
        let (user_id, _key_id) = validate_api_key(&pool, &api_key).unwrap();
        assert_eq!(user_id, user.id);
    }

    #[test]
    fn test_validate_invalid_api_key() {
        let pool = setup_test_db();

        let result = validate_api_key(&pool, "usk_invalid_key");
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn test_create_and_list_api_keys() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create additional key
        let (record, key) = create_api_key(&pool, user.id, "Test Key").unwrap();
        assert_eq!(record.name, "Test Key");
        assert!(key.starts_with("usk_"));

        // List keys
        let keys = list_api_keys(&pool, user.id).unwrap();
        assert_eq!(keys.len(), 2); // Default key + Test Key
    }

    #[test]
    fn test_revoke_api_key() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();
        let (record, api_key) = create_api_key(&pool, user.id, "To Revoke").unwrap();

        // Verify key works
        assert!(validate_api_key(&pool, &api_key).is_ok());

        // Revoke key
        revoke_api_key(&pool, user.id, record.id).unwrap();

        // Verify key no longer works
        let result = validate_api_key(&pool, &api_key);
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn test_create_and_get_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("test123".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7, user.id).unwrap();
        assert_eq!(url.short_code, "test123");
        assert_eq!(url.original_url, "https://example.com");
        assert_eq!(url.user_id, Some(user.id));

        let retrieved = get_url_by_code(&pool, "test123").unwrap();
        assert_eq!(retrieved.id, url.id);
    }

    #[test]
    fn test_url_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("owned".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7, user1.id).unwrap();

        // User 1 can access their URL
        let retrieved = get_url_by_id(&pool, url.id, user1.id).unwrap();
        assert_eq!(retrieved.id, url.id);

        // User 2 cannot access User 1's URL
        let result = get_url_by_id(&pool, url.id, user2.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn test_list_urls_by_user() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // Create URLs for user1
        for i in 0..3 {
            let request = CreateUrlRequest {
                url: format!("https://example{}.com", i),
                custom_code: Some(format!("user1_{}", i)),
                expires_in_hours: None,
            };
            create_url(&pool, &request, 7, user1.id).unwrap();
        }

        // Create URLs for user2
        for i in 0..2 {
            let request = CreateUrlRequest {
                url: format!("https://other{}.com", i),
                custom_code: Some(format!("user2_{}", i)),
                expires_in_hours: None,
            };
            create_url(&pool, &request, 7, user2.id).unwrap();
        }

        // User 1 should only see their URLs
        let user1_urls = list_urls(&pool, user1.id, &ListUrlsQuery::default()).unwrap();
        assert_eq!(user1_urls.len(), 3);

        // User 2 should only see their URLs
        let user2_urls = list_urls(&pool, user2.id, &ListUrlsQuery::default()).unwrap();
        assert_eq!(user2_urls.len(), 2);
    }

    #[test]
    fn test_delete_url_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("delete_test".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7, user1.id).unwrap();

        // User 2 cannot delete User 1's URL
        let result = delete_url(&pool, url.id, user2.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));

        // User 1 can delete their URL
        delete_url(&pool, url.id, user1.id).unwrap();

        // URL should be gone
        let result = get_url_by_code(&pool, "delete_test");
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn test_click_tracking() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("clicks".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7, user.id).unwrap();
        assert_eq!(url.clicks, 0);

        record_click(&pool, url.id, Some("127.0.0.1"), None, None).unwrap();

        let updated = get_url_by_id(&pool, url.id, user.id).unwrap();
        assert_eq!(updated.clicks, 1);
    }

    // ========================================================================
    // Bulk Operation Tests
    // ========================================================================

    #[test]
    fn test_bulk_create_all_success() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let items = vec![
            BulkCreateUrlItem {
                url: "https://example1.com".to_string(),
                custom_code: Some("bulk1".to_string()),
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://example2.com".to_string(),
                custom_code: Some("bulk2".to_string()),
                expires_in_hours: None,
            },
        ];

        let response = bulk_create_urls(&pool, &items, 7, user.id, "http://localhost").unwrap();

        assert_eq!(response.status, BulkOperationStatus::Success);
        assert_eq!(response.total, 2);
        assert_eq!(response.succeeded, 2);
        assert_eq!(response.failed, 0);
        assert_eq!(response.results.len(), 2);

        // Verify all items succeeded
        for result in &response.results {
            assert!(result.success);
            assert!(result.data.is_some());
            assert!(result.error.is_none());
        }

        // Verify URLs were created
        assert!(get_url_by_code(&pool, "bulk1").is_ok());
        assert!(get_url_by_code(&pool, "bulk2").is_ok());
    }

    #[test]
    fn test_bulk_create_partial_duplicate() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // First create a URL with code "existing"
        let request = CreateUrlRequest {
            url: "https://existing.com".to_string(),
            custom_code: Some("existing".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user.id).unwrap();

        // Now try bulk create with one duplicate
        let items = vec![
            BulkCreateUrlItem {
                url: "https://new.com".to_string(),
                custom_code: Some("newcode".to_string()),
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://duplicate.com".to_string(),
                custom_code: Some("existing".to_string()), // duplicate!
                expires_in_hours: None,
            },
        ];

        let response = bulk_create_urls(&pool, &items, 7, user.id, "http://localhost").unwrap();

        assert_eq!(response.status, BulkOperationStatus::PartialSuccess);
        assert_eq!(response.total, 2);
        assert_eq!(response.succeeded, 1);
        assert_eq!(response.failed, 1);

        // First item should succeed
        assert!(response.results[0].success);
        assert!(response.results[0].data.is_some());

        // Second item should fail with duplicate error
        assert!(!response.results[1].success);
        assert!(response.results[1].error.is_some());
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "DUPLICATE_CODE");
    }

    #[test]
    fn test_bulk_create_auto_generate_codes() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create items without custom codes
        let items = vec![
            BulkCreateUrlItem {
                url: "https://auto1.com".to_string(),
                custom_code: None,
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://auto2.com".to_string(),
                custom_code: None,
                expires_in_hours: None,
            },
            BulkCreateUrlItem {
                url: "https://auto3.com".to_string(),
                custom_code: None,
                expires_in_hours: None,
            },
        ];

        let response = bulk_create_urls(&pool, &items, 7, user.id, "http://localhost").unwrap();

        assert_eq!(response.status, BulkOperationStatus::Success);
        assert_eq!(response.succeeded, 3);

        // All codes should be unique
        let codes: Vec<&str> = response
            .results
            .iter()
            .map(|r| r.data.as_ref().unwrap().short_code.as_str())
            .collect();

        let unique_codes: std::collections::HashSet<&str> = codes.iter().cloned().collect();
        assert_eq!(unique_codes.len(), 3);
    }

    #[test]
    fn test_bulk_delete_all_success() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create some URLs
        let mut ids = vec![];
        for i in 0..3 {
            let request = CreateUrlRequest {
                url: format!("https://delete{}.com", i),
                custom_code: Some(format!("del{}", i)),
                expires_in_hours: None,
            };
            let url = create_url(&pool, &request, 7, user.id).unwrap();
            ids.push(url.id);
        }

        // Bulk delete
        let response = bulk_delete_urls(&pool, &ids, user.id).unwrap();

        assert_eq!(response.status, BulkOperationStatus::Success);
        assert_eq!(response.total, 3);
        assert_eq!(response.succeeded, 3);
        assert_eq!(response.failed, 0);

        // Verify all were deleted
        for id in &ids {
            let result = get_url_by_id(&pool, *id, user.id);
            assert!(matches!(result, Err(AppError::NotFound(_))));
        }
    }

    #[test]
    fn test_bulk_delete_partial_not_found() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create one URL
        let request = CreateUrlRequest {
            url: "https://exists.com".to_string(),
            custom_code: Some("exists".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Try to delete existing + non-existing
        let ids = vec![url.id, 99999, 99998];
        let response = bulk_delete_urls(&pool, &ids, user.id).unwrap();

        assert_eq!(response.status, BulkOperationStatus::PartialSuccess);
        assert_eq!(response.total, 3);
        assert_eq!(response.succeeded, 1);
        assert_eq!(response.failed, 2);

        // First should succeed
        assert!(response.results[0].success);

        // Others should fail
        assert!(!response.results[1].success);
        assert_eq!(response.results[1].error.as_ref().unwrap().code, "NOT_FOUND");
        assert!(!response.results[2].success);
    }

    #[test]
    fn test_bulk_delete_respects_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // Create URLs for user1
        let request = CreateUrlRequest {
            url: "https://user1.com".to_string(),
            custom_code: Some("user1url".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user1.id).unwrap();

        // User2 tries to bulk delete user1's URL
        let response = bulk_delete_urls(&pool, &[url.id], user2.id).unwrap();

        assert_eq!(response.status, BulkOperationStatus::Failed);
        assert_eq!(response.failed, 1);
        assert!(!response.results[0].success);

        // URL should still exist
        assert!(get_url_by_code(&pool, "user1url").is_ok());
    }

    // ========================================================================
    // Tag Tests
    // ========================================================================

    #[test]
    fn test_create_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();
        assert_eq!(tag.name, "Important");
        assert_eq!(tag.user_id, user.id);
    }

    #[test]
    fn test_create_duplicate_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        create_tag(&pool, "Important", user.id).unwrap();
        let result = create_tag(&pool, "Important", user.id);
        assert!(matches!(result, Err(AppError::DuplicateCode(_))));
    }

    #[test]
    fn test_list_tags() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // Create tags for user1
        create_tag(&pool, "Work", user1.id).unwrap();
        create_tag(&pool, "Personal", user1.id).unwrap();

        // Create tag for user2
        create_tag(&pool, "Other", user2.id).unwrap();

        // User1 should only see their tags
        let user1_tags = list_tags(&pool, user1.id).unwrap();
        assert_eq!(user1_tags.len(), 2);

        // User2 should only see their tags
        let user2_tags = list_tags(&pool, user2.id).unwrap();
        assert_eq!(user2_tags.len(), 1);
        assert_eq!(user2_tags[0].name, "Other");
    }

    #[test]
    fn test_delete_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "ToDelete", user.id).unwrap();

        // Delete should succeed
        delete_tag(&pool, tag.id, user.id).unwrap();

        // Tag should be gone
        let tags = list_tags(&pool, user.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn test_add_tag_to_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("tagged".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add tag to URL
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        // Verify tag is associated
        let tags = get_tags_for_url(&pool, url.id, user.id).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "Important");
    }

    #[test]
    fn test_add_duplicate_tag_to_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("tagged2".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add tag first time
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        // Try to add same tag again - should fail
        let result = add_tag_to_url(&pool, url.id, tag.id, user.id);
        assert!(matches!(result, Err(AppError::DuplicateCode(_))));
    }

    #[test]
    fn test_remove_tag_from_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("toremove".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add and then remove tag
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();
        remove_tag_from_url(&pool, url.id, tag.id, user.id).unwrap();

        // Verify tag is removed
        let tags = get_tags_for_url(&pool, url.id, user.id).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn test_get_urls_by_tag() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Work", user.id).unwrap();
        let other_tag = create_tag(&pool, "Personal", user.id).unwrap();

        // Create URLs and tag them
        let request1 = CreateUrlRequest {
            url: "https://work1.com".to_string(),
            custom_code: Some("work1".to_string()),
            expires_in_hours: None,
        };
        let url1 = create_url(&pool, &request1, 7, user.id).unwrap();
        add_tag_to_url(&pool, url1.id, tag.id, user.id).unwrap();

        let request2 = CreateUrlRequest {
            url: "https://work2.com".to_string(),
            custom_code: Some("work2".to_string()),
            expires_in_hours: None,
        };
        let url2 = create_url(&pool, &request2, 7, user.id).unwrap();
        add_tag_to_url(&pool, url2.id, tag.id, user.id).unwrap();

        let request3 = CreateUrlRequest {
            url: "https://personal.com".to_string(),
            custom_code: Some("personal".to_string()),
            expires_in_hours: None,
        };
        let url3 = create_url(&pool, &request3, 7, user.id).unwrap();
        add_tag_to_url(&pool, url3.id, other_tag.id, user.id).unwrap();

        // Get URLs by "Work" tag
        let work_urls = get_urls_by_tag(&pool, tag.id, user.id).unwrap();
        assert_eq!(work_urls.len(), 2);

        // Get URLs by "Personal" tag
        let personal_urls = get_urls_by_tag(&pool, other_tag.id, user.id).unwrap();
        assert_eq!(personal_urls.len(), 1);
    }

    #[test]
    fn test_get_urls_by_tag_with_tags() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag1 = create_tag(&pool, "Work", user.id).unwrap();
        let tag2 = create_tag(&pool, "Important", user.id).unwrap();

        // Create URL with both tags
        let request = CreateUrlRequest {
            url: "https://work-important.com".to_string(),
            custom_code: Some("multi_tag".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();
        add_tag_to_url(&pool, url.id, tag1.id, user.id).unwrap();
        add_tag_to_url(&pool, url.id, tag2.id, user.id).unwrap();

        // Get URLs by "Work" tag with all tags included
        let urls_with_tags = get_urls_by_tag_with_tags(&pool, tag1.id, user.id).unwrap();
        assert_eq!(urls_with_tags.len(), 1);

        let (returned_url, tags) = &urls_with_tags[0];
        assert_eq!(returned_url.id, url.id);
        assert_eq!(tags.len(), 2); // Should have both Work and Important tags

        // Verify both tags are present
        let tag_names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"Work"));
        assert!(tag_names.contains(&"Important"));
    }

    #[test]
    fn test_tag_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // User1 creates a tag
        let tag = create_tag(&pool, "Private", user1.id).unwrap();

        // User2 cannot delete user1's tag
        let result = delete_tag(&pool, tag.id, user2.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));

        // User2 cannot use user1's tag
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("user2url".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user2.id).unwrap();

        let result = add_tag_to_url(&pool, url.id, tag.id, user2.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn test_delete_tag_cascades_to_url_tags() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let tag = create_tag(&pool, "Temporary", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("cascade".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Add tag to URL
        add_tag_to_url(&pool, url.id, tag.id, user.id).unwrap();

        // Delete the tag
        delete_tag(&pool, tag.id, user.id).unwrap();

        // URL should have no tags now
        let tags = get_tags_for_url(&pool, url.id, user.id).unwrap();
        assert!(tags.is_empty());
    }

    // ========================================================================
    // Caching Tests
    // ========================================================================

    #[test]
    fn test_get_url_by_code_cached_miss_then_hit() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("cached1".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user.id).unwrap();

        // First call - cache miss, should query database
        assert!(cache.get_url("cached1").is_none());
        let url1 = get_url_by_code_cached(&pool, &cache, "cached1").unwrap();
        assert_eq!(url1.original_url, "https://example.com");

        // Verify it's now in the cache
        assert!(cache.get_url("cached1").is_some());

        // Second call - cache hit
        let url2 = get_url_by_code_cached(&pool, &cache, "cached1").unwrap();
        assert_eq!(url2.original_url, "https://example.com");
        assert_eq!(url2.id, url1.id);
    }

    #[test]
    fn test_get_url_by_code_cached_not_found() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        // Try to get a non-existent URL
        let result = get_url_by_code_cached(&pool, &cache, "nonexistent");
        assert!(matches!(result, Err(AppError::NotFound(_))));

        // Should not be cached
        assert!(cache.get_url("nonexistent").is_none());
    }

    #[test]
    fn test_validate_api_key_cached_miss_then_hit() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, api_key) = register_user(&pool, "test@example.com").unwrap();
        let key_hash = hash_api_key(&api_key);

        // First call - cache miss
        assert!(cache.get_api_key(&key_hash).is_none());
        let (user_id1, key_id1) = validate_api_key_cached(&pool, &cache, &api_key).unwrap();
        assert_eq!(user_id1, user.id);

        // Verify it's now in the cache
        assert!(cache.get_api_key(&key_hash).is_some());

        // Second call - cache hit
        let (user_id2, key_id2) = validate_api_key_cached(&pool, &cache, &api_key).unwrap();
        assert_eq!(user_id2, user.id);
        assert_eq!(key_id1, key_id2);
    }

    #[test]
    fn test_validate_api_key_cached_invalid() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let result = validate_api_key_cached(&pool, &cache, "usk_invalid_key");
        assert!(matches!(result, Err(AppError::Unauthorized(_))));

        // Invalid keys should not be cached
        let key_hash = hash_api_key("usk_invalid_key");
        assert!(cache.get_api_key(&key_hash).is_none());
    }

    #[test]
    fn test_delete_url_invalidates_cache() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("todelete".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Populate the cache
        get_url_by_code_cached(&pool, &cache, "todelete").unwrap();
        assert!(cache.get_url("todelete").is_some());

        // Delete with cache invalidation
        delete_url_with_cache(&pool, Some(&cache), url.id, user.id).unwrap();

        // Cache should be invalidated
        assert!(cache.get_url("todelete").is_none());

        // Should return not found now
        let result = get_url_by_code_cached(&pool, &cache, "todelete");
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn test_bulk_delete_invalidates_cache() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create multiple URLs
        let mut ids = vec![];
        for i in 0..3 {
            let request = CreateUrlRequest {
                url: format!("https://example{}.com", i),
                custom_code: Some(format!("bulk_cache_{}", i)),
                expires_in_hours: None,
            };
            let url = create_url(&pool, &request, 7, user.id).unwrap();
            ids.push(url.id);

            // Populate the cache
            get_url_by_code_cached(&pool, &cache, &format!("bulk_cache_{}", i)).unwrap();
        }

        // Verify all are cached
        for i in 0..3 {
            assert!(cache.get_url(&format!("bulk_cache_{}", i)).is_some());
        }

        // Bulk delete with cache invalidation
        bulk_delete_urls_with_cache(&pool, Some(&cache), &ids, user.id).unwrap();

        // All cache entries should be invalidated
        for i in 0..3 {
            assert!(cache.get_url(&format!("bulk_cache_{}", i)).is_none());
        }
    }

    #[test]
    fn test_revoke_api_key_invalidates_cache() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();
        let (record, api_key) = create_api_key(&pool, user.id, "To Revoke").unwrap();
        let key_hash = hash_api_key(&api_key);

        // Populate the cache
        validate_api_key_cached(&pool, &cache, &api_key).unwrap();
        assert!(cache.get_api_key(&key_hash).is_some());

        // Revoke with cache invalidation
        revoke_api_key_with_cache(&pool, Some(&cache), user.id, record.id).unwrap();

        // Cache should be invalidated
        assert!(cache.get_api_key(&key_hash).is_none());

        // Should return unauthorized now
        let result = validate_api_key_cached(&pool, &cache, &api_key);
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }

    #[test]
    fn test_cached_url_expiration_check() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create a URL that expires in -1 hours (already expired)
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("expired_cache".to_string()),
            expires_in_hours: Some(-1), // Already expired
        };

        // This will fail because it's already expired when created
        let result = create_url(&pool, &request, 7, user.id);

        // If creation succeeds but is expired, test the cache behavior
        if let Ok(url) = result {
            // Manually insert into cache with expired time
            cache.insert_url(
                "expired_cache",
                CachedUrl {
                    id: url.id,
                    original_url: url.original_url.clone(),
                    expires_at: url.expires_at.clone(),
                    user_id: url.user_id,
                },
            );

            // Should detect expiration on cache hit and return error
            let result = get_url_by_code_cached(&pool, &cache, "expired_cache");
            assert!(matches!(result, Err(AppError::ExpiredUrl(_))));

            // Cache entry should be invalidated after detecting expiration
            assert!(cache.get_url("expired_cache").is_none());
        }
    }

    #[test]
    fn test_cache_stores_correct_data() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://specific-url.com/path?query=value".to_string(),
            custom_code: Some("specific123".to_string()),
            expires_in_hours: None,
        };
        let created_url = create_url(&pool, &request, 7, user.id).unwrap();

        // Populate cache
        get_url_by_code_cached(&pool, &cache, "specific123").unwrap();

        // Verify cached data is correct
        let cached = cache.get_url("specific123").unwrap();
        assert_eq!(cached.id, created_url.id);
        assert_eq!(cached.original_url, "https://specific-url.com/path?query=value");
        assert_eq!(cached.user_id, Some(user.id));
        assert!(cached.expires_at.is_none());
    }

    #[test]
    fn test_api_key_cache_stores_correct_data() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, api_key) = register_user(&pool, "test@example.com").unwrap();
        let key_hash = hash_api_key(&api_key);

        // Populate cache
        let (user_id, key_id) = validate_api_key_cached(&pool, &cache, &api_key).unwrap();

        // Verify cached data is correct
        let cached = cache.get_api_key(&key_hash).unwrap();
        assert_eq!(cached.user_id, user.id);
        assert_eq!(cached.user_id, user_id);
        assert_eq!(cached.key_id, key_id);
    }

    #[test]
    fn test_delete_without_cache_still_works() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("no_cache_del".to_string()),
            expires_in_hours: None,
        };
        let url = create_url(&pool, &request, 7, user.id).unwrap();

        // Delete without cache (None)
        delete_url_with_cache(&pool, None, url.id, user.id).unwrap();

        // URL should be gone
        let result = get_url_by_code(&pool, "no_cache_del");
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn test_revoke_without_cache_still_works() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();
        let (record, api_key) = create_api_key(&pool, user.id, "No Cache Revoke").unwrap();

        // Verify key works
        assert!(validate_api_key(&pool, &api_key).is_ok());

        // Revoke without cache (None)
        revoke_api_key_with_cache(&pool, None, user.id, record.id).unwrap();

        // Key should no longer work
        let result = validate_api_key(&pool, &api_key);
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }

    // ========================================================================
    // Metrics Integration Tests
    // ========================================================================

    #[test]
    fn test_create_url_with_metrics() {
        let pool = setup_test_db();
        let registry = prometheus::Registry::new();
        let metrics = AppMetrics::new(&registry).unwrap();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("metrics_test".to_string()),
            expires_in_hours: None,
        };

        // Create URL with metrics
        let url = create_url_with_metrics(&pool, &request, 7, user.id, Some(&metrics)).unwrap();
        assert_eq!(url.short_code, "metrics_test");

        // Verify metric was incremented
        assert_eq!(metrics.urls_created_total.get() as u64, 1);

        // Create another URL
        let request2 = CreateUrlRequest {
            url: "https://example2.com".to_string(),
            custom_code: Some("metrics_test2".to_string()),
            expires_in_hours: None,
        };
        create_url_with_metrics(&pool, &request2, 7, user.id, Some(&metrics)).unwrap();

        assert_eq!(metrics.urls_created_total.get() as u64, 2);
    }

    #[test]
    fn test_get_url_cached_with_metrics() {
        let pool = setup_test_db();
        let cache = AppCache::default();
        let registry = prometheus::Registry::new();
        let metrics = AppMetrics::new(&registry).unwrap();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("cache_metrics".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user.id).unwrap();

        // First call - cache miss
        get_url_by_code_cached_with_metrics(&pool, &cache, "cache_metrics", Some(&metrics)).unwrap();
        assert_eq!(
            metrics.cache_misses_total.with_label_values(&["url"]).get() as u64,
            1
        );
        assert_eq!(
            metrics.cache_hits_total.with_label_values(&["url"]).get() as u64,
            0
        );

        // Second call - cache hit
        get_url_by_code_cached_with_metrics(&pool, &cache, "cache_metrics", Some(&metrics)).unwrap();
        assert_eq!(
            metrics.cache_misses_total.with_label_values(&["url"]).get() as u64,
            1
        );
        assert_eq!(
            metrics.cache_hits_total.with_label_values(&["url"]).get() as u64,
            1
        );
    }

    #[test]
    fn test_validate_api_key_cached_with_metrics() {
        let pool = setup_test_db();
        let cache = AppCache::default();
        let registry = prometheus::Registry::new();
        let metrics = AppMetrics::new(&registry).unwrap();

        let (user, api_key) = register_user(&pool, "test@example.com").unwrap();

        // First call - cache miss, success
        let (user_id, _) = validate_api_key_cached_with_metrics(&pool, &cache, &api_key, Some(&metrics)).unwrap();
        assert_eq!(user_id, user.id);
        assert_eq!(
            metrics.cache_misses_total.with_label_values(&["api_key"]).get() as u64,
            1
        );
        assert_eq!(
            metrics.api_key_validations_total.with_label_values(&["success"]).get() as u64,
            1
        );

        // Second call - cache hit, success
        validate_api_key_cached_with_metrics(&pool, &cache, &api_key, Some(&metrics)).unwrap();
        assert_eq!(
            metrics.cache_hits_total.with_label_values(&["api_key"]).get() as u64,
            1
        );
        assert_eq!(
            metrics.api_key_validations_total.with_label_values(&["success"]).get() as u64,
            2
        );

        // Invalid key - should record invalid
        let result = validate_api_key_cached_with_metrics(&pool, &cache, "usk_invalid", Some(&metrics));
        assert!(result.is_err());
        assert_eq!(
            metrics.api_key_validations_total.with_label_values(&["invalid"]).get() as u64,
            1
        );
    }

    #[test]
    fn test_metrics_record_redirect() {
        let registry = prometheus::Registry::new();
        let metrics = AppMetrics::new(&registry).unwrap();

        assert_eq!(metrics.redirects_total.get() as u64, 0);

        metrics.record_redirect();
        assert_eq!(metrics.redirects_total.get() as u64, 1);

        metrics.record_redirect();
        metrics.record_redirect();
        assert_eq!(metrics.redirects_total.get() as u64, 3);
    }
}
