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
use crate::models::{ApiKeyRecord, ClickLog, CreateUrlRequest, ListUrlsQuery, Url, User};
use crate::queries::{ApiKeys, ClickLogs, Urls, Users};

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
        .query_row(
            "SELECT COUNT(*) FROM users WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )
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

    let record = conn.query_row(
        "SELECT id, user_id, key_hash, name, created_at, last_used_at, is_active FROM api_keys WHERE id = ?1",
        params![key_id],
        |row| {
            Ok(ApiKeyRecord {
                id: row.get(0)?,
                user_id: row.get(1)?,
                key_hash: row.get(2)?,
                name: row.get(3)?,
                created_at: row.get(4)?,
                last_used_at: row.get(5)?,
                is_active: row.get::<_, i32>(6)? == 1,
            })
        },
    )?;

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
            "SELECT COUNT(*) FROM api_keys WHERE id = ?1 AND user_id = ?2",
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
}
