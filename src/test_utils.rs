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
