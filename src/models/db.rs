//! Database entity structs (rows mapped from SQLite).

use serde::{Deserialize, Serialize};

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
    /// Parsed browser name
    pub browser: Option<String>,
    /// Parsed browser version
    pub browser_version: Option<String>,
    /// Parsed operating system
    pub os: Option<String>,
    /// Device type (desktop, mobile, bot, other)
    pub device_type: Option<String>,
    /// Extracted referer domain
    pub referer_domain: Option<String>,
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
