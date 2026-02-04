//! Business logic layer for URL operations.
//!
//! Contains all the core functionality for creating, retrieving,
//! and managing shortened URLs, users, and API keys.

use chrono::{Duration, Utc};
use nanoid::nanoid;
use rand::Rng;
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
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
    let user = conn.query_row(Users::SELECT_BY_ID, params![user_id], |row| {
        Ok(User {
            id: row.get(0)?,
            email: row.get(1)?,
            created_at: row.get(2)?,
        })
    })?;

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

    conn.query_row(Users::SELECT_BY_ID, params![user_id], |row| {
        Ok(User {
            id: row.get(0)?,
            email: row.get(1)?,
            created_at: row.get(2)?,
        })
    })
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

    let record = conn.query_row(ApiKeys::SELECT_BY_ID, params![key_id], |row| {
        Ok(ApiKeyRecord {
            id: row.get(0)?,
            user_id: row.get(1)?,
            key_hash: row.get(2)?,
            name: row.get(3)?,
            created_at: row.get(4)?,
            last_used_at: row.get(5)?,
            is_active: row.get::<_, i32>(6)? == 1,
        })
    })?;

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

/// List all API keys for a user
pub fn list_api_keys(pool: &DbPool, user_id: i64) -> Result<Vec<ApiKeyRecord>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(ApiKeys::SELECT_BY_USER)?;

    let keys = stmt
        .query_map(params![user_id], |row| {
            Ok(ApiKeyRecord {
                id: row.get(0)?,
                user_id: row.get(1)?,
                key_hash: row.get(2)?,
                name: row.get(3)?,
                created_at: row.get(4)?,
                last_used_at: row.get(5)?,
                is_active: row.get::<_, i32>(6)? == 1,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys)
}

/// Revoke an API key
pub fn revoke_api_key(pool: &DbPool, user_id: i64, key_id: i64) -> Result<(), AppError> {
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

    let rows_affected = conn.execute(ApiKeys::DEACTIVATE, params![key_id, user_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "API key with ID '{}' not found or already revoked",
            key_id
        )));
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
        .query_row(Urls::SELECT_BY_CODE, params![short_code], |row| {
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
        })
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

/// Get a URL by its ID (for API - checks ownership)
pub fn get_url_by_id(pool: &DbPool, id: i64, user_id: i64) -> Result<Url, AppError> {
    let conn = get_conn(pool)?;

    conn.query_row(Urls::SELECT_BY_ID_AND_USER, params![id, user_id], |row| {
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
    })
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
        .query_map(params![user_id, limit, offset], |row| {
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
        })?
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
        .query_map(params![url_id, limit], |row| {
            Ok(ClickLog {
                id: row.get(0)?,
                url_id: row.get(1)?,
                clicked_at: row.get(2)?,
                ip_address: row.get(3)?,
                user_agent: row.get(4)?,
                referer: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(logs)
}

/// Delete a URL by ID (checks ownership)
pub fn delete_url(pool: &DbPool, id: i64, user_id: i64) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    let rows_affected = conn.execute(Urls::DELETE_BY_ID_AND_USER, params![id, user_id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            id
        )));
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
    let mut results = Vec::with_capacity(ids.len());
    let mut succeeded = 0;
    let mut failed = 0;

    for &id in ids {
        match delete_url(pool, id, user_id) {
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

    let tag = conn.query_row(Tags::SELECT_BY_ID, params![tag_id], |row| {
        Ok(Tag {
            id: row.get(0)?,
            name: row.get(1)?,
            user_id: row.get(2)?,
            created_at: row.get(3)?,
        })
    })?;

    log::info!("Created tag '{}' for user {}", name, user_id);
    Ok(tag)
}

/// List all tags for a user
pub fn list_tags(pool: &DbPool, user_id: i64) -> Result<Vec<Tag>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(Tags::SELECT_BY_USER)?;

    let tags = stmt
        .query_map(params![user_id], |row| {
            Ok(Tag {
                id: row.get(0)?,
                name: row.get(1)?,
                user_id: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?
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
    let url_exists: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM urls WHERE id = ?1 AND user_id = ?2",
            params![url_id, user_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if url_exists == 0 {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    // Verify the tag belongs to the user
    let tag_exists: i32 = conn
        .query_row(Tags::COUNT_BY_ID_AND_USER, params![tag_id, user_id], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if tag_exists == 0 {
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
    let url_exists: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM urls WHERE id = ?1 AND user_id = ?2",
            params![url_id, user_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if url_exists == 0 {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    // Verify the tag belongs to the user
    let tag_exists: i32 = conn
        .query_row(Tags::COUNT_BY_ID_AND_USER, params![tag_id, user_id], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if tag_exists == 0 {
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
    let url_exists: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM urls WHERE id = ?1 AND user_id = ?2",
            params![url_id, user_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if url_exists == 0 {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            url_id
        )));
    }

    let mut stmt = conn.prepare(UrlTags::SELECT_TAGS_BY_URL)?;

    let tags = stmt
        .query_map(params![url_id], |row| {
            Ok(Tag {
                id: row.get(0)?,
                name: row.get(1)?,
                user_id: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(tags)
}

/// Get all URLs with a specific tag
pub fn get_urls_by_tag(pool: &DbPool, tag_id: i64, user_id: i64) -> Result<Vec<Url>, AppError> {
    let conn = get_conn(pool)?;

    // Verify the tag belongs to the user
    let tag_exists: i32 = conn
        .query_row(Tags::COUNT_BY_ID_AND_USER, params![tag_id, user_id], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if tag_exists == 0 {
        return Err(AppError::NotFound(format!(
            "Tag with ID '{}' not found",
            tag_id
        )));
    }

    let mut stmt = conn.prepare(UrlTags::SELECT_URLS_BY_TAG)?;

    let urls = stmt
        .query_map(params![tag_id, user_id], |row| {
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
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(urls)
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
}
