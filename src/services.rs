//! Business logic layer for URL operations.
//!
//! Contains all the core functionality for creating, retrieving,
//! and managing shortened URLs.

use chrono::{Duration, Utc};
use nanoid::nanoid;
use rusqlite::params;

use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
use crate::models::{ClickLog, CreateUrlRequest, ListUrlsQuery, Url};
use crate::queries::{ClickLogs, Urls};

/// Characters used for generating short codes (URL-safe)
const ALPHABET: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
    'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z',
];

/// Generate a random short code using nanoid
///
/// # Arguments
/// * `length` - The desired length of the short code
///
/// # Returns
/// A random alphanumeric string
pub fn generate_short_code(length: usize) -> String {
    nanoid!(length, &ALPHABET)
}

/// Create a new shortened URL
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `request` - The URL creation request
/// * `code_length` - Length of auto-generated codes
///
/// # Returns
/// * `Result<Url, AppError>` - The created URL or an error
pub fn create_url(
    pool: &DbPool,
    request: &CreateUrlRequest,
    code_length: usize,
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

    conn.execute(Urls::INSERT, params![short_code, request.url, expires_at])?;

    // Retrieve the created URL
    let url = get_url_by_code(pool, &short_code)?;
    log::info!("Created short URL: {} -> {}", short_code, request.url);

    Ok(url)
}

/// Check if a short code already exists
fn code_exists(conn: &rusqlite::Connection, code: &str) -> Result<bool, AppError> {
    let count: i32 = conn.query_row(Urls::COUNT_BY_CODE, params![code], |row| row.get(0))?;
    Ok(count > 0)
}

/// Get a URL by its short code
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `short_code` - The short code to look up
///
/// # Returns
/// * `Result<Url, AppError>` - The URL or NotFound error
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
                })
            },
        )
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

/// Get a URL by its ID
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `id` - The URL ID
///
/// # Returns
/// * `Result<Url, AppError>` - The URL or NotFound error
pub fn get_url_by_id(pool: &DbPool, id: i64) -> Result<Url, AppError> {
    let conn = get_conn(pool)?;

    conn.query_row(Urls::SELECT_BY_ID, params![id], |row| {
            Ok(Url {
                id: row.get(0)?,
                short_code: row.get(1)?,
                original_url: row.get(2)?,
                clicks: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                expires_at: row.get(6)?,
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            AppError::NotFound(format!("URL with ID '{}' not found", id))
        }
        _ => AppError::DatabaseError(e.to_string()),
    })
}

/// List all URLs with pagination
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `query` - Pagination and sorting options
///
/// # Returns
/// * `Result<Vec<Url>, AppError>` - List of URLs
pub fn list_urls(pool: &DbPool, query: &ListUrlsQuery) -> Result<Vec<Url>, AppError> {
    let conn = get_conn(pool)?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = (page - 1) * limit;
    let sort_order = match query.sort.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    let sql = Urls::list_with_order(sort_order);
    let mut stmt = conn.prepare(&sql)?;
    let urls = stmt
        .query_map(params![limit, offset], |row| {
            Ok(Url {
                id: row.get(0)?,
                short_code: row.get(1)?,
                original_url: row.get(2)?,
                clicks: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                expires_at: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(urls)
}

/// Get total count of URLs
pub fn count_urls(pool: &DbPool) -> Result<usize, AppError> {
    let conn = get_conn(pool)?;
    let count: i64 = conn.query_row(Urls::COUNT_ALL, [], |row| row.get(0))?;
    Ok(count as usize)
}

/// Increment click count and optionally log the click
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `url_id` - The URL ID
/// * `ip_address` - Optional visitor IP
/// * `user_agent` - Optional user agent string
/// * `referer` - Optional referer header
pub fn record_click(
    pool: &DbPool,
    url_id: i64,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    referer: Option<&str>,
) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    conn.execute(Urls::INCREMENT_CLICKS, params![url_id])?;
    conn.execute(
        ClickLogs::INSERT,
        params![url_id, ip_address, user_agent, referer],
    )?;

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

/// Delete a URL by ID
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `id` - The URL ID to delete
///
/// # Returns
/// * `Result<(), AppError>` - Success or NotFound error
pub fn delete_url(pool: &DbPool, id: i64) -> Result<(), AppError> {
    let conn = get_conn(pool)?;

    let rows_affected = conn.execute(Urls::DELETE_BY_ID, params![id])?;

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "URL with ID '{}' not found",
            id
        )));
    }

    log::info!("Deleted URL with ID: {}", id);
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
    fn test_create_and_get_url() {
        let pool = setup_test_db();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("test123".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7).unwrap();
        assert_eq!(url.short_code, "test123");
        assert_eq!(url.original_url, "https://example.com");

        let retrieved = get_url_by_code(&pool, "test123").unwrap();
        assert_eq!(retrieved.id, url.id);
    }

    #[test]
    fn test_duplicate_code_error() {
        let pool = setup_test_db();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("dupe".to_string()),
            expires_in_hours: None,
        };

        create_url(&pool, &request, 7).unwrap();

        let result = create_url(&pool, &request, 7);
        assert!(matches!(result, Err(AppError::DuplicateCode(_))));
    }

    #[test]
    fn test_click_tracking() {
        let pool = setup_test_db();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("clicks".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7).unwrap();
        assert_eq!(url.clicks, 0);

        record_click(&pool, url.id, Some("127.0.0.1"), None, None).unwrap();

        let updated = get_url_by_id(&pool, url.id).unwrap();
        assert_eq!(updated.clicks, 1);
    }

    #[test]
    fn test_delete_url() {
        let pool = setup_test_db();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("delete_me".to_string()),
            expires_in_hours: None,
        };

        let url = create_url(&pool, &request, 7).unwrap();
        delete_url(&pool, url.id).unwrap();

        let result = get_url_by_id(&pool, url.id);
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
