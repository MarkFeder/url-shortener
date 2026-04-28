//! Bulk operation request/response DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

use super::url::CreateUrlResponse;
use super::validators::{validate_alphanumeric, validate_positive_hours};

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
    #[validate(custom(function = "validate_positive_hours"))]
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
