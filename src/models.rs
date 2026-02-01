//! Data models and DTOs (Data Transfer Objects) for the URL shortener.
//!
//! Contains structures for database entities and API request/response types.

use serde::{Deserialize, Serialize};
use validator::Validate;

// ============================================================================
// Database Models
// ============================================================================

/// Represents a shortened URL in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Url {
    /// Unique identifier
    pub id: i64,
    /// The short code (e.g., "abc123")
    pub short_code: String,
    /// The original long URL
    pub original_url: String,
    /// Number of times this URL has been accessed
    pub clicks: i64,
    /// When the URL was created
    pub created_at: String,
    /// When the URL was last updated
    pub updated_at: String,
    /// Optional expiration date
    pub expires_at: Option<String>,
}

/// Represents a click log entry for analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickLog {
    /// Unique identifier
    pub id: i64,
    /// Foreign key to the URL
    pub url_id: i64,
    /// When the click occurred
    pub clicked_at: String,
    /// IP address of the visitor (if available)
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Referer header
    pub referer: Option<String>,
}

// ============================================================================
// API Request DTOs
// ============================================================================

/// Request body for creating a new short URL
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUrlRequest {
    /// The URL to shorten (must be a valid URL)
    #[validate(url(message = "Invalid URL format"))]
    #[validate(length(max = 2048, message = "URL is too long (max 2048 characters)"))]
    pub url: String,

    /// Optional custom short code
    #[validate(length(min = 3, max = 20, message = "Custom code must be 3-20 characters"))]
    #[validate(custom(function = "validate_alphanumeric"))]
    pub custom_code: Option<String>,

    /// Optional expiration time in hours
    pub expires_in_hours: Option<i64>,
}

/// Custom validator for alphanumeric codes (letters, numbers, underscore, hyphen)
fn validate_alphanumeric(code: &str) -> Result<(), validator::ValidationError> {
    lazy_static::lazy_static! {
        static ref ALPHANUMERIC_REGEX: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    }
    if ALPHANUMERIC_REGEX.is_match(code) {
        Ok(())
    } else {
        Err(validator::ValidationError::new("Custom code must be alphanumeric (letters, numbers, underscore, hyphen)"))
    }
}

// ============================================================================
// API Response DTOs
// ============================================================================

/// Response for a successfully created short URL
#[derive(Debug, Clone, Serialize)]
pub struct CreateUrlResponse {
    /// The short code
    pub short_code: String,
    /// The full short URL
    pub short_url: String,
    /// The original URL
    pub original_url: String,
    /// When the URL was created
    pub created_at: String,
    /// When the URL expires (if set)
    pub expires_at: Option<String>,
}

/// Response containing URL details
#[derive(Debug, Clone, Serialize)]
pub struct UrlResponse {
    /// Unique identifier
    pub id: i64,
    /// The short code
    pub short_code: String,
    /// The full short URL
    pub short_url: String,
    /// The original URL
    pub original_url: String,
    /// Number of clicks
    pub clicks: i64,
    /// When created
    pub created_at: String,
    /// When last updated
    pub updated_at: String,
    /// When expires (if set)
    pub expires_at: Option<String>,
}

impl UrlResponse {
    /// Create a UrlResponse from a Url entity and base URL
    pub fn from_url(url: Url, base_url: &str) -> Self {
        Self {
            id: url.id,
            short_code: url.short_code.clone(),
            short_url: format!("{}/{}", base_url, url.short_code),
            original_url: url.original_url,
            clicks: url.clicks,
            created_at: url.created_at,
            updated_at: url.updated_at,
            expires_at: url.expires_at,
        }
    }
}

/// Response for listing multiple URLs
#[derive(Debug, Clone, Serialize)]
pub struct UrlListResponse {
    /// Total count of URLs
    pub total: usize,
    /// List of URLs
    pub urls: Vec<UrlResponse>,
}

/// Generic API error response
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
    /// Error code (for programmatic handling)
    pub code: String,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: code.into(),
        }
    }
}

/// Generic success message response
#[derive(Debug, Clone, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing URLs
#[derive(Debug, Clone, Deserialize)]
pub struct ListUrlsQuery {
    /// Page number (1-indexed)
    pub page: Option<u32>,
    /// Items per page
    pub limit: Option<u32>,
    /// Sort order: "asc" or "desc"
    pub sort: Option<String>,
}

impl Default for ListUrlsQuery {
    fn default() -> Self {
        Self {
            page: Some(1),
            limit: Some(20),
            sort: Some("desc".to_string()),
        }
    }
}
