//! Generic shared response types.

use serde::Serialize;

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
