//! URL request/response DTOs and query parameters.

use serde::{Deserialize, Serialize};
use validator::Validate;

use super::db::Url;
use super::validators::{validate_alphanumeric, validate_positive_hours};
use crate::constants::{DEFAULT_PAGE_LIMIT, DEFAULT_SORT_ORDER};

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
    #[validate(custom(function = "validate_positive_hours"))]
    pub expires_in_hours: Option<i64>,
}

/// Request body for updating an existing URL's destination
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateUrlRequest {
    /// The new destination URL (must be a valid URL)
    #[validate(url(message = "Invalid URL format"))]
    #[validate(length(max = 2048, message = "URL is too long (max 2048 characters)"))]
    pub url: String,
}

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
            limit: Some(DEFAULT_PAGE_LIMIT),
            sort: Some(DEFAULT_SORT_ORDER.to_string()),
        }
    }
}

/// Query parameters for searching URLs
#[derive(Debug, Clone, Deserialize)]
pub struct SearchUrlsQuery {
    /// Search term for original URL (case-insensitive contains)
    pub q: Option<String>,
    /// Search term for short code (case-insensitive contains)
    pub code: Option<String>,
    /// Maximum number of results (default: 20, max: 100)
    pub limit: Option<u32>,
}
