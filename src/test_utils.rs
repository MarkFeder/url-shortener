//! Test utilities and helpers.
//!
//! Provides common test infrastructure used across multiple test modules.
//! This module is only compiled when running tests.

#![cfg(test)]

use crate::cache::AppCache;
use crate::config::Config;
use crate::constants::TEST_DB_URL;
use crate::db::{init_pool, run_migrations, DbPool};

/// Create an in-memory database pool for testing.
///
/// Initializes a new SQLite in-memory database and runs all migrations.
/// Each call creates a fresh database instance.
pub fn setup_test_db() -> DbPool {
    let pool = init_pool(TEST_DB_URL).expect("Failed to create test pool");
    run_migrations(&pool).expect("Failed to run migrations");
    pool
}

/// Alias for `setup_test_db` for consistency with auth module naming.
pub fn setup_test_pool() -> DbPool {
    setup_test_db()
}

/// Create a default test configuration.
pub fn test_config() -> Config {
    Config::default()
}

/// Create a default test cache.
pub fn test_cache() -> AppCache {
    AppCache::default()
}

/// Helper to create a test user and return their credentials.
///
/// Returns (User, api_key) tuple.
pub fn create_test_user(pool: &DbPool, email: &str) -> (crate::models::User, String) {
    crate::services::register_user(pool, email).expect("Failed to create test user")
}

/// Helper to create a test URL for a user.
///
/// Returns the created URL.
pub fn create_test_url(
    pool: &DbPool,
    user_id: i64,
    original_url: &str,
    custom_code: Option<&str>,
    short_code_length: usize,
) -> crate::models::Url {
    let request = crate::models::CreateUrlRequest {
        url: original_url.to_string(),
        custom_code: custom_code.map(|s| s.to_string()),
        expires_in_hours: None,
    };
    crate::services::create_url(pool, &request, short_code_length, user_id)
        .expect("Failed to create test URL")
}

/// Record a single test click with specific parameters.
pub fn record_test_click(
    pool: &DbPool,
    url_id: i64,
    user_agent: Option<&str>,
    referer: Option<&str>,
) {
    crate::services::record_click(pool, url_id, Some("127.0.0.1"), user_agent, referer)
        .expect("Failed to record test click");
}

/// Record varied test clicks with diverse UA/referer data.
pub fn record_varied_test_clicks(pool: &DbPool, url_id: i64) {
    let clicks = [
        (
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            Some("https://google.com/search?q=test"),
        ),
        (
            Some("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"),
            Some("https://twitter.com/post/123"),
        ),
        (
            Some("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            None,
        ),
        (
            Some("Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0"),
            Some("https://google.com/search?q=other"),
        ),
        (None, None),
    ];

    for (ua, referer) in clicks {
        record_test_click(pool, url_id, ua, referer);
    }
}

/// Extension trait for test assertions.
pub trait TestAssertions {
    /// Assert that a result is Ok.
    fn assert_ok(&self);
    /// Assert that a result is Err.
    fn assert_err(&self);
}

impl<T, E: std::fmt::Debug> TestAssertions for Result<T, E> {
    fn assert_ok(&self) {
        assert!(self.is_ok(), "Expected Ok, got Err: {:?}", self.as_ref().err());
    }

    fn assert_err(&self) {
        assert!(self.is_err(), "Expected Err, got Ok");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        create_test_url, create_test_user, setup_test_db, setup_test_pool, test_cache,
        test_config, TestAssertions,
    };

    #[test]
    fn test_setup_test_db() {
        let pool = setup_test_db();
        assert!(pool.get().is_ok());
    }

    #[test]
    fn test_setup_test_pool_alias() {
        let pool = setup_test_pool();
        assert!(pool.get().is_ok());
    }

    #[test]
    fn test_test_config() {
        let config = test_config();
        assert_eq!(config.short_code_length, 7);
    }

    #[test]
    fn test_test_cache() {
        let _cache = test_cache();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_create_test_user() {
        let pool = setup_test_db();
        let (user, api_key) = create_test_user(&pool, "test@example.com");
        assert!(user.id > 0);
        assert!(api_key.starts_with("usk_"));
    }

    #[test]
    fn test_create_test_url() {
        let pool = setup_test_db();
        let (user, _) = create_test_user(&pool, "test@example.com");
        let url = create_test_url(&pool, user.id, "https://example.com", None, 7);
        assert_eq!(url.original_url, "https://example.com");
        assert_eq!(url.short_code.len(), 7);
    }

    #[test]
    fn test_assertions() {
        let ok_result: Result<i32, &str> = Ok(42);
        ok_result.assert_ok();

        let err_result: Result<i32, &str> = Err("error");
        err_result.assert_err();
    }
}
