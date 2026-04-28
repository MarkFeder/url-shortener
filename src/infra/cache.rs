//! In-memory caching module for URL lookups and API key validation.
//!
//! Uses `moka` for lock-free concurrent caching with TTL support.

use moka::sync::Cache;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached URL data for redirect lookups
#[derive(Clone, Debug)]
pub struct CachedUrl {
    pub id: i64,
    pub original_url: String,
    pub expires_at: Option<String>,
    pub user_id: Option<i64>,
}

/// Cached API key validation result
#[derive(Clone, Debug)]
pub struct CachedApiKey {
    pub user_id: i64,
    pub key_id: i64,
    pub last_validated_at: Instant,
}

/// Application cache combining URL and API key caches
#[derive(Clone)]
pub struct AppCache {
    /// Cache for URL lookups by short_code
    pub url_cache: Arc<Cache<String, CachedUrl>>,
    /// Cache for API key validation by key_hash
    pub api_key_cache: Arc<Cache<String, CachedApiKey>>,
}

impl AppCache {
    /// Create a new AppCache with the specified settings
    pub fn new(
        url_cache_ttl_secs: u64,
        url_cache_max_capacity: u64,
        api_key_cache_ttl_secs: u64,
        api_key_cache_max_capacity: u64,
    ) -> Self {
        let url_cache = Cache::builder()
            .max_capacity(url_cache_max_capacity)
            .time_to_live(Duration::from_secs(url_cache_ttl_secs))
            .build();

        let api_key_cache = Cache::builder()
            .max_capacity(api_key_cache_max_capacity)
            .time_to_live(Duration::from_secs(api_key_cache_ttl_secs))
            .build();

        Self {
            url_cache: Arc::new(url_cache),
            api_key_cache: Arc::new(api_key_cache),
        }
    }

    /// Insert a URL into the cache
    pub fn insert_url(&self, short_code: &str, cached_url: CachedUrl) {
        self.url_cache.insert(short_code.to_string(), cached_url);
    }

    /// Get a URL from the cache
    pub fn get_url(&self, short_code: &str) -> Option<CachedUrl> {
        self.url_cache.get(short_code)
    }

    /// Invalidate a URL from the cache
    pub fn invalidate_url(&self, short_code: &str) {
        self.url_cache.invalidate(short_code);
    }

    /// Insert an API key validation result into the cache
    pub fn insert_api_key(&self, key_hash: &str, cached_key: CachedApiKey) {
        self.api_key_cache.insert(key_hash.to_string(), cached_key);
    }

    /// Get an API key validation result from the cache
    pub fn get_api_key(&self, key_hash: &str) -> Option<CachedApiKey> {
        self.api_key_cache.get(key_hash)
    }

    /// Invalidate an API key from the cache
    pub fn invalidate_api_key(&self, key_hash: &str) {
        self.api_key_cache.invalidate(key_hash);
    }
}

impl Default for AppCache {
    fn default() -> Self {
        Self::new(
            300,    // URL cache TTL: 5 minutes
            10_000, // URL cache max capacity
            600,    // API key cache TTL: 10 minutes
            1_000,  // API key cache max capacity
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_url_cache_insert_and_get() {
        let cache = AppCache::default();

        let cached_url = CachedUrl {
            id: 1,
            original_url: "https://example.com".to_string(),
            expires_at: None,
            user_id: Some(1),
        };

        cache.insert_url("abc123", cached_url.clone());

        let retrieved = cache.get_url("abc123");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, 1);
        assert_eq!(retrieved.original_url, "https://example.com");
    }

    #[test]
    fn test_url_cache_miss() {
        let cache = AppCache::default();
        let retrieved = cache.get_url("nonexistent");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_url_cache_invalidation() {
        let cache = AppCache::default();

        let cached_url = CachedUrl {
            id: 1,
            original_url: "https://example.com".to_string(),
            expires_at: None,
            user_id: Some(1),
        };

        cache.insert_url("abc123", cached_url);
        assert!(cache.get_url("abc123").is_some());

        cache.invalidate_url("abc123");
        assert!(cache.get_url("abc123").is_none());
    }

    #[test]
    fn test_api_key_cache_insert_and_get() {
        let cache = AppCache::default();

        let cached_key = CachedApiKey {
            user_id: 1,
            key_id: 42,
            last_validated_at: Instant::now(),
        };

        cache.insert_api_key("hash123", cached_key.clone());

        let retrieved = cache.get_api_key("hash123");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.user_id, 1);
        assert_eq!(retrieved.key_id, 42);
    }

    #[test]
    fn test_api_key_cache_invalidation() {
        let cache = AppCache::default();

        let cached_key = CachedApiKey {
            user_id: 1,
            key_id: 42,
            last_validated_at: Instant::now(),
        };

        cache.insert_api_key("hash123", cached_key);
        assert!(cache.get_api_key("hash123").is_some());

        cache.invalidate_api_key("hash123");
        assert!(cache.get_api_key("hash123").is_none());
    }

    #[test]
    fn test_cache_ttl_expiration() {
        // Create cache with 1 second TTL
        let cache = AppCache::new(1, 100, 1, 100);

        let cached_url = CachedUrl {
            id: 1,
            original_url: "https://example.com".to_string(),
            expires_at: None,
            user_id: Some(1),
        };

        cache.insert_url("ttl_test", cached_url);
        assert!(cache.get_url("ttl_test").is_some());

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(1100));

        // Entry should be expired
        assert!(cache.get_url("ttl_test").is_none());
    }
}
