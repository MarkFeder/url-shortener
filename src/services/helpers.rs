//! Shared utilities used across all service domains.
//!
//! Contains ownership checks and key/code generation. Row mapping helpers
//! live next to the domain that owns them (e.g. `services::urls::map_url_row`).

use nanoid::nanoid;
use rand::Rng;
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::constants::{API_KEY_PREFIX, API_KEY_RANDOM_LENGTH, SHORT_CODE_ALPHABET};
use crate::errors::AppError;

/// Check if a resource exists and belongs to the user
pub(super) fn check_ownership(
    conn: &rusqlite::Connection,
    query: &str,
    id: i64,
    user_id: i64,
) -> Result<bool, AppError> {
    let count: i32 = conn.query_row(query, params![id, user_id], |row| row.get(0))?;
    Ok(count > 0)
}

/// Generate a random short code using nanoid
pub fn generate_short_code(length: usize) -> String {
    nanoid!(length, &SHORT_CODE_ALPHABET)
}

/// Generate a new API key with the usk_ prefix
pub fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let key: String = (0..API_KEY_RANDOM_LENGTH)
        .map(|_| {
            let idx = rng.gen_range(0..SHORT_CODE_ALPHABET.len());
            SHORT_CODE_ALPHABET[idx]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
