//! Tag request/response DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

use super::db::Tag;

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
