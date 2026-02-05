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
    /// User who owns this URL
    pub user_id: Option<i64>,
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

/// Represents a user in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier
    pub id: i64,
    /// User's email address
    pub email: String,
    /// When the user was created
    pub created_at: String,
}

/// Represents an API key record in the database
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    /// Unique identifier
    pub id: i64,
    /// Foreign key to the user
    pub user_id: i64,
    /// SHA-256 hash of the API key
    pub key_hash: String,
    /// Human-readable name for the key
    pub name: String,
    /// When the key was created
    pub created_at: String,
    /// When the key was last used
    pub last_used_at: Option<String>,
    /// Whether the key is active
    pub is_active: bool,
}

/// Represents a tag in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    /// Unique identifier
    pub id: i64,
    /// Tag name
    pub name: String,
    /// User who owns this tag
    pub user_id: i64,
    /// When the tag was created
    pub created_at: String,
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

/// Request body for user registration
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RegisterRequest {
    /// Email address (must be valid format)
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email is too long (max 255 characters)"))]
    pub email: String,
}

/// Request body for creating a new API key
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the key
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,
}

/// Request body for creating a new tag
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateTagRequest {
    /// Tag name (1-50 characters)
    #[validate(length(min = 1, max = 50, message = "Tag name must be 1-50 characters"))]
    pub name: String,
}

/// Request body for adding a tag to a URL
#[derive(Debug, Clone, Deserialize)]
pub struct AddTagToUrlRequest {
    /// ID of the tag to add
    pub tag_id: i64,
}

// ============================================================================
// API Response DTOs
// ============================================================================

/// Response for a successfully created short URL
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Response for user registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// User ID
    pub user_id: i64,
    /// User's email
    pub email: String,
    /// The generated API key (only shown once)
    pub api_key: String,
}

/// Response for API key details (without the actual key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyResponse {
    /// Key ID
    pub id: i64,
    /// Human-readable name
    pub name: String,
    /// When created
    pub created_at: String,
    /// When last used
    pub last_used_at: Option<String>,
    /// Whether the key is active
    pub is_active: bool,
}

impl ApiKeyResponse {
    pub fn from_record(record: &ApiKeyRecord) -> Self {
        Self {
            id: record.id,
            name: record.name.clone(),
            created_at: record.created_at.clone(),
            last_used_at: record.last_used_at.clone(),
            is_active: record.is_active,
        }
    }
}

/// Response for creating a new API key (includes the actual key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    /// Key ID
    pub id: i64,
    /// Human-readable name
    pub name: String,
    /// The generated API key (only shown once)
    pub api_key: String,
    /// When created
    pub created_at: String,
}

/// Response for listing API keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyListResponse {
    /// List of API keys
    pub keys: Vec<ApiKeyResponse>,
}

/// Response for a tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagResponse {
    /// Tag ID
    pub id: i64,
    /// Tag name
    pub name: String,
    /// When created
    pub created_at: String,
}

impl TagResponse {
    pub fn from_tag(tag: &Tag) -> Self {
        Self {
            id: tag.id,
            name: tag.name.clone(),
            created_at: tag.created_at.clone(),
        }
    }
}

/// Response for listing tags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagListResponse {
    /// List of tags
    pub tags: Vec<TagResponse>,
}

/// Response for URLs with tags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlWithTagsResponse {
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
    /// Tags associated with this URL
    pub tags: Vec<TagResponse>,
}

/// Response for listing URLs by tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlsByTagResponse {
    /// List of URLs
    pub urls: Vec<UrlWithTagsResponse>,
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

/// Query parameters for QR code generation
#[derive(Debug, Clone, Deserialize)]
pub struct QrCodeQuery {
    /// Output format: "png" (default) or "svg"
    pub format: Option<String>,
    /// Size in pixels (default: 256, min: 64, max: 1024)
    pub size: Option<u32>,
}

// ============================================================================
// Bulk Operation DTOs
// ============================================================================

/// Single item in a bulk create request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct BulkCreateUrlItem {
    /// The URL to shorten (must be a valid URL)
    #[validate(url(message = "Invalid URL format"))]
    #[validate(length(max = 2048, message = "URL is too long"))]
    pub url: String,
    /// Optional custom short code
    #[validate(length(min = 3, max = 20, message = "Custom code must be 3-20 characters"))]
    #[validate(custom(function = "validate_alphanumeric"))]
    pub custom_code: Option<String>,
    /// Optional expiration time in hours
    pub expires_in_hours: Option<i64>,
}

/// Request body for bulk creating URLs
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct BulkCreateUrlRequest {
    /// List of URLs to create (1-100)
    #[validate(length(min = 1, max = 100, message = "Must provide 1-100 URLs"))]
    #[validate(nested)]
    pub urls: Vec<BulkCreateUrlItem>,
}

/// Request body for bulk deleting URLs
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct BulkDeleteUrlRequest {
    /// List of URL IDs to delete (1-100)
    #[validate(length(min = 1, max = 100, message = "Must provide 1-100 IDs"))]
    pub ids: Vec<i64>,
}

/// Status of a bulk operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BulkOperationStatus {
    /// All items succeeded
    Success,
    /// Some items succeeded, some failed
    PartialSuccess,
    /// All items failed
    Failed,
}

/// Error details for a failed bulk item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkItemError {
    /// Error code (e.g., "DUPLICATE_CODE", "VALIDATION_ERROR")
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

/// Result for a single item in a bulk create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateItemResult {
    /// Index of the item in the original request
    pub index: usize,
    /// Whether this item was created successfully
    pub success: bool,
    /// Created URL data (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data: Option<CreateUrlResponse>,
    /// Error details (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub error: Option<BulkItemError>,
}

/// Result for a single item in a bulk delete operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteItemResult {
    /// ID of the URL that was attempted to be deleted
    pub id: i64,
    /// Whether this item was deleted successfully
    pub success: bool,
    /// Error details (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub error: Option<BulkItemError>,
}

/// Response for a bulk create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateUrlResponse {
    /// Overall status of the operation
    pub status: BulkOperationStatus,
    /// Total number of items in the request
    pub total: usize,
    /// Number of items that succeeded
    pub succeeded: usize,
    /// Number of items that failed
    pub failed: usize,
    /// Per-item results
    pub results: Vec<BulkCreateItemResult>,
}

/// Response for a bulk delete operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteUrlResponse {
    /// Overall status of the operation
    pub status: BulkOperationStatus,
    /// Total number of items in the request
    pub total: usize,
    /// Number of items that succeeded
    pub succeeded: usize,
    /// Number of items that failed
    pub failed: usize,
    /// Per-item results
    pub results: Vec<BulkDeleteItemResult>,
}
