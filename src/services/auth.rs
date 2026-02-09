//! User registration and API key management services.

use std::time::Instant;

use rusqlite::params;

use super::helpers::{
    generate_api_key, hash_api_key, map_api_key_row, map_user_row,
};
use crate::cache::{AppCache, CachedApiKey};
use crate::constants::DEFAULT_API_KEY_NAME;
use crate::db::{get_conn, DbPool};
use crate::errors::AppError;
use crate::metrics::AppMetrics;
use crate::models::{ApiKeyRecord, User};
use crate::queries::{ApiKeys, Users};

/// Threshold for refreshing last_used_at on cache hits (5 minutes)
const LAST_USED_REFRESH_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(300);

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
        .query_row(Users::COUNT_BY_EMAIL, params![email], |row| row.get(0))?;

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
        params![user_id, key_hash, DEFAULT_API_KEY_NAME],
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

        // Refresh last_used_at if stale
        if cached.last_validated_at.elapsed() > LAST_USED_REFRESH_THRESHOLD {
            if let Ok(conn) = get_conn(pool) {
                let _ = conn.execute(ApiKeys::UPDATE_LAST_USED, params![cached.key_id]);
            }
            cache.insert_api_key(
                &key_hash,
                CachedApiKey {
                    user_id: cached.user_id,
                    key_id: cached.key_id,
                    last_validated_at: Instant::now(),
                },
            );
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
                CachedApiKey {
                    user_id,
                    key_id,
                    last_validated_at: Instant::now(),
                },
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
        )?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::AppCache;
    use crate::metrics::AppMetrics;
    use crate::test_utils::setup_test_db;

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
    fn test_cache_hit_updates_last_used_at_after_threshold() {
        let pool = setup_test_db();
        let cache = AppCache::default();

        let (user, api_key) = register_user(&pool, "test@example.com").unwrap();
        let key_hash = hash_api_key(&api_key);

        // Populate cache via a normal validation
        let (user_id, key_id) = validate_api_key_cached(&pool, &cache, &api_key).unwrap();
        assert_eq!(user_id, user.id);

        // Manually set last_validated_at to 6 minutes ago to simulate staleness
        let stale_entry = CachedApiKey {
            user_id,
            key_id,
            last_validated_at: Instant::now() - std::time::Duration::from_secs(360),
        };
        cache.insert_api_key(&key_hash, stale_entry);

        // Clear last_used_at in DB so we can detect the refresh
        let conn = crate::db::get_conn(&pool).unwrap();
        conn.execute(
            "UPDATE api_keys SET last_used_at = NULL WHERE id = ?1",
            params![key_id],
        )
        .unwrap();

        // Validate again — should trigger last_used_at refresh
        let (user_id2, key_id2) = validate_api_key_cached(&pool, &cache, &api_key).unwrap();
        assert_eq!(user_id2, user.id);
        assert_eq!(key_id2, key_id);

        // Verify DB last_used_at was updated
        let last_used: Option<String> = conn
            .query_row(
                "SELECT last_used_at FROM api_keys WHERE id = ?1",
                params![key_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(last_used.is_some(), "last_used_at should have been refreshed");

        // Verify the cached entry was refreshed (last_validated_at should be recent)
        let cached = cache.get_api_key(&key_hash).unwrap();
        assert!(
            cached.last_validated_at.elapsed() < std::time::Duration::from_secs(5),
            "cached last_validated_at should be recent"
        );
    }
}
