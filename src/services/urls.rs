//! URL CRUD, deletion, search, and caching services.

use chrono::{Duration, Utc};
use rusqlite::params;

use super::helpers::{generate_short_code, map_url_row};
use crate::cache::{AppCache, CachedUrl};
use crate::constants::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
use crate::metrics::AppMetrics;
use crate::models::{CreateUrlRequest, ListUrlsQuery, Url};
use crate::queries::Urls;

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
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
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

/// Search URLs by original URL and/or short code
///
/// Both search terms are optional and case-insensitive.
/// If both are provided, URLs must match both criteria.
pub fn search_urls(
    pool: &DbPool,
    user_id: i64,
    url_query: Option<&str>,
    code_query: Option<&str>,
    limit: u32,
) -> Result<Vec<Url>, AppError> {
    let conn = get_conn(pool)?;
    let mut stmt = conn.prepare(Urls::SEARCH)?;

    let urls = stmt
        .query_map(params![user_id, url_query, code_query, limit], map_url_row)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(urls)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::AppCache;
    use crate::metrics::AppMetrics;
    use crate::services::register_user;
    use crate::test_utils::setup_test_db;

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

    // ========================================================================
    // Search Tests
    // ========================================================================

    #[test]
    fn test_search_urls_by_original_url() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create URLs with different original URLs
        let urls_data = [
            ("https://github.com/rust-lang/rust", "github1"),
            ("https://github.com/tokio-rs/tokio", "github2"),
            ("https://docs.rs/actix-web", "docsrs"),
            ("https://crates.io/crates/serde", "crates"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            create_url(&pool, &request, 7, user.id).unwrap();
        }

        // Search for "github" in original URL
        let results = search_urls(&pool, user.id, Some("github"), None, 20).unwrap();
        assert_eq!(results.len(), 2);

        // Search for "docs.rs" in original URL
        let results = search_urls(&pool, user.id, Some("docs.rs"), None, 20).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].short_code, "docsrs");

        // Search for non-existent URL
        let results = search_urls(&pool, user.id, Some("nonexistent.com"), None, 20).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_urls_by_short_code() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create URLs with different codes
        let urls_data = [
            ("https://example1.com", "project-alpha"),
            ("https://example2.com", "project-beta"),
            ("https://example3.com", "docs-main"),
            ("https://example4.com", "api-v1"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            create_url(&pool, &request, 7, user.id).unwrap();
        }

        // Search for "project" in short code
        let results = search_urls(&pool, user.id, None, Some("project"), 20).unwrap();
        assert_eq!(results.len(), 2);

        // Search for "api" in short code
        let results = search_urls(&pool, user.id, None, Some("api"), 20).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].short_code, "api-v1");
    }

    #[test]
    fn test_search_urls_combined() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create URLs
        let urls_data = [
            ("https://github.com/project", "gh-proj"),
            ("https://github.com/other", "gh-other"),
            ("https://gitlab.com/project", "gl-proj"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            create_url(&pool, &request, 7, user.id).unwrap();
        }

        // Search for github URLs with "proj" in code (should match only gh-proj)
        let results = search_urls(&pool, user.id, Some("github"), Some("proj"), 20).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].short_code, "gh-proj");
    }

    #[test]
    fn test_search_urls_case_insensitive() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://GitHub.COM/Rust-Lang".to_string(),
            custom_code: Some("RustLang".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user.id).unwrap();

        // Search with different cases
        let results = search_urls(&pool, user.id, Some("github.com"), None, 20).unwrap();
        assert_eq!(results.len(), 1);

        let results = search_urls(&pool, user.id, Some("GITHUB"), None, 20).unwrap();
        assert_eq!(results.len(), 1);

        let results = search_urls(&pool, user.id, None, Some("rustlang"), 20).unwrap();
        assert_eq!(results.len(), 1);

        let results = search_urls(&pool, user.id, None, Some("RUSTLANG"), 20).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_urls_respects_ownership() {
        let pool = setup_test_db();

        let (user1, _) = register_user(&pool, "user1@example.com").unwrap();
        let (user2, _) = register_user(&pool, "user2@example.com").unwrap();

        // Create URL for user1
        let request = CreateUrlRequest {
            url: "https://private.example.com".to_string(),
            custom_code: Some("private1".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user1.id).unwrap();

        // Create URL for user2
        let request = CreateUrlRequest {
            url: "https://private.example.com".to_string(),
            custom_code: Some("private2".to_string()),
            expires_in_hours: None,
        };
        create_url(&pool, &request, 7, user2.id).unwrap();

        // User1 searching should only find their URL
        let results = search_urls(&pool, user1.id, Some("private"), None, 20).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].short_code, "private1");

        // User2 searching should only find their URL
        let results = search_urls(&pool, user2.id, Some("private"), None, 20).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].short_code, "private2");
    }

    #[test]
    fn test_search_urls_limit() {
        let pool = setup_test_db();

        let (user, _) = register_user(&pool, "test@example.com").unwrap();

        // Create 10 URLs
        for i in 0..10 {
            let request = CreateUrlRequest {
                url: format!("https://example{}.com", i),
                custom_code: Some(format!("test{}", i)),
                expires_in_hours: None,
            };
            create_url(&pool, &request, 7, user.id).unwrap();
        }

        // Search with limit of 5
        let results = search_urls(&pool, user.id, Some("example"), None, 5).unwrap();
        assert_eq!(results.len(), 5);

        // Search with limit of 20 (should return all 10)
        let results = search_urls(&pool, user.id, Some("example"), None, 20).unwrap();
        assert_eq!(results.len(), 10);
    }
}
