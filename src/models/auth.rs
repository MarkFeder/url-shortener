//! Auth (registration + API key) request/response DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

use super::db::ApiKeyRecord;
use crate::infra::constants::{MAX_API_KEY_NAME_LENGTH, MAX_EMAIL_LENGTH};

/// Request body for user registration
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct RegisterRequest {
    /// Email address (must be valid format)
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = MAX_EMAIL_LENGTH, message = "Email is too long"))]
    pub email: String,
}

/// Request body for creating a new API key
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the key
    #[validate(length(min = 1, max = MAX_API_KEY_NAME_LENGTH, message = "Name length is out of range"))]
    pub name: String,
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
