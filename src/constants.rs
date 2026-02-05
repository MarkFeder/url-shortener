//! Application-wide constants.
//!
//! Centralizes magic numbers and strings for better maintainability.

// ============================================================================
// API Key Constants
// ============================================================================

/// Prefix for all generated API keys
pub const API_KEY_PREFIX: &str = "usk_";

/// Length of the random portion of an API key (excluding prefix)
pub const API_KEY_RANDOM_LENGTH: usize = 32;

/// Length of a SHA-256 hash in hexadecimal characters
pub const SHA256_HEX_LENGTH: usize = 64;

// ============================================================================
// Pagination Constants
// ============================================================================

/// Default number of items per page for list endpoints
pub const DEFAULT_PAGE_LIMIT: u32 = 20;

/// Maximum allowed items per page
pub const MAX_PAGE_LIMIT: u32 = 100;

/// Default page number (1-indexed)
pub const DEFAULT_PAGE: u32 = 1;

/// Default sort order for list queries
pub const DEFAULT_SORT_ORDER: &str = "desc";

// ============================================================================
// QR Code Constants
// ============================================================================

/// Default QR code size in pixels
pub const DEFAULT_QR_SIZE: u32 = 256;

/// Minimum allowed QR code size in pixels
pub const MIN_QR_SIZE: u32 = 64;

/// Maximum allowed QR code size in pixels
pub const MAX_QR_SIZE: u32 = 1024;

// ============================================================================
// URL Validation Constants
// ============================================================================

/// Maximum allowed URL length in characters
pub const MAX_URL_LENGTH: usize = 2048;

/// Minimum length for custom short codes
pub const MIN_CUSTOM_CODE_LENGTH: usize = 3;

/// Maximum length for custom short codes
pub const MAX_CUSTOM_CODE_LENGTH: usize = 20;

// ============================================================================
// Bulk Operation Constants
// ============================================================================

/// Minimum number of items in a bulk operation
pub const MIN_BULK_ITEMS: usize = 1;

/// Maximum number of items in a bulk operation
pub const MAX_BULK_ITEMS: usize = 100;

// ============================================================================
// Short Code Generation Constants
// ============================================================================

/// Characters used for generating short codes (URL-safe alphanumeric)
pub const SHORT_CODE_ALPHABET: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];

/// Maximum retry attempts when generating a unique short code
pub const MAX_CODE_GENERATION_RETRIES: u32 = 10;

// ============================================================================
// API Key Name Constants
// ============================================================================

/// Maximum length for API key names
pub const MAX_API_KEY_NAME_LENGTH: usize = 100;

/// Default name for the first API key created during registration
pub const DEFAULT_API_KEY_NAME: &str = "Default key";

// ============================================================================
// Tag Constants
// ============================================================================

/// Maximum length for tag names
pub const MAX_TAG_NAME_LENGTH: usize = 50;

// ============================================================================
// Test Constants
// ============================================================================

/// In-memory SQLite database URL for tests
#[cfg(test)]
pub const TEST_DB_URL: &str = "file::memory:?cache=shared";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alphabet_length() {
        // Ensure alphabet contains exactly 62 characters (0-9, a-z, A-Z)
        assert_eq!(SHORT_CODE_ALPHABET.len(), 62);
    }

    #[test]
    fn test_pagination_constants() {
        assert!(DEFAULT_PAGE_LIMIT <= MAX_PAGE_LIMIT);
        assert!(DEFAULT_PAGE >= 1);
    }

    #[test]
    fn test_qr_size_constants() {
        assert!(MIN_QR_SIZE <= DEFAULT_QR_SIZE);
        assert!(DEFAULT_QR_SIZE <= MAX_QR_SIZE);
    }

    #[test]
    fn test_bulk_constants() {
        assert!(MIN_BULK_ITEMS <= MAX_BULK_ITEMS);
    }

    #[test]
    fn test_custom_code_constants() {
        assert!(MIN_CUSTOM_CODE_LENGTH <= MAX_CUSTOM_CODE_LENGTH);
    }
}
