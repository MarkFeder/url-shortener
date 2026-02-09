//! Custom error types for the URL shortener application.
//!
//! Implements proper error handling with automatic HTTP response conversion.

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use std::fmt;

use crate::models::ErrorResponse;

/// Application-level errors
#[derive(Debug)]
pub enum AppError {
    /// URL was not found
    NotFound(String),
    /// Invalid input data
    ValidationError(String),
    /// Database operation failed
    DatabaseError(String),
    /// Short code already exists
    DuplicateCode(String),
    /// URL has expired
    ExpiredUrl(String),
    /// Internal server error
    InternalError(String),
    /// Unauthorized access
    Unauthorized(String),
    /// Forbidden - authenticated but not allowed
    Forbidden(String),
    /// Email already registered
    EmailAlreadyExists(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AppError::DuplicateCode(msg) => write!(f, "Duplicate code: {}", msg),
            AppError::ExpiredUrl(msg) => write!(f, "URL expired: {}", msg),
            AppError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::EmailAlreadyExists(msg) => write!(f, "Email already exists: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

// ============================================================================
// Constructor Methods
// ============================================================================

impl AppError {
    /// Create a NotFound error for a URL
    pub fn url_not_found(short_code: &str) -> Self {
        AppError::NotFound(format!("URL with code '{}' not found", short_code))
    }

    /// Create a NotFound error for a URL by ID
    pub fn url_not_found_by_id(id: i64) -> Self {
        AppError::NotFound(format!("URL with ID '{}' not found", id))
    }

    /// Create a NotFound error for a user
    pub fn user_not_found(user_id: i64) -> Self {
        AppError::NotFound(format!("User with ID '{}' not found", user_id))
    }

    /// Create a NotFound error for a tag
    pub fn tag_not_found(tag_id: i64) -> Self {
        AppError::NotFound(format!("Tag with ID '{}' not found", tag_id))
    }

    /// Create an ExpiredUrl error
    pub fn url_expired(short_code: &str) -> Self {
        AppError::ExpiredUrl(format!("URL '{}' has expired", short_code))
    }

    /// Create a DuplicateCode error
    pub fn duplicate_code(code: &str) -> Self {
        AppError::DuplicateCode(format!("Short code '{}' already exists", code))
    }

    /// Create an Unauthorized error for invalid API key
    pub fn invalid_api_key() -> Self {
        AppError::Unauthorized("Invalid API key".into())
    }

    /// Create an Unauthorized error for missing API key
    pub fn missing_api_key() -> Self {
        AppError::Unauthorized(
            "Missing API key. Provide via 'Authorization: Bearer <key>' or 'X-API-Key: <key>' header".into()
        )
    }

    /// Create a Forbidden error for resource ownership violation
    pub fn not_owner(resource_type: &str) -> Self {
        AppError::Forbidden(format!(
            "You do not have permission to access this {}",
            resource_type
        ))
    }

    /// Create a ValidationError with a message
    pub fn validation(message: impl Into<String>) -> Self {
        AppError::ValidationError(message.into())
    }

    /// Create an InternalError with a message
    pub fn internal(message: impl Into<String>) -> Self {
        AppError::InternalError(message.into())
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::DuplicateCode(_) => StatusCode::CONFLICT,
            AppError::ExpiredUrl(_) => StatusCode::GONE,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::EmailAlreadyExists(_) => StatusCode::CONFLICT,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let (error_code, message) = match self {
            AppError::NotFound(msg) => ("NOT_FOUND", msg.clone()),
            AppError::ValidationError(msg) => ("VALIDATION_ERROR", msg.clone()),
            AppError::DatabaseError(msg) => ("DATABASE_ERROR", msg.clone()),
            AppError::DuplicateCode(msg) => ("DUPLICATE_CODE", msg.clone()),
            AppError::ExpiredUrl(msg) => ("EXPIRED_URL", msg.clone()),
            AppError::InternalError(msg) => ("INTERNAL_ERROR", msg.clone()),
            AppError::Unauthorized(msg) => ("UNAUTHORIZED", msg.clone()),
            AppError::Forbidden(msg) => ("FORBIDDEN", msg.clone()),
            AppError::EmailAlreadyExists(msg) => ("EMAIL_ALREADY_EXISTS", msg.clone()),
        };

        HttpResponse::build(self.status_code()).json(ErrorResponse::new(message, error_code))
    }
}

/// Convert rusqlite errors to AppError
impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(sqlite_err, _) = &err {
            if sqlite_err.code == rusqlite::ErrorCode::ConstraintViolation {
                log::warn!("Constraint violation: {:?}", err);
                return AppError::DuplicateCode(
                    "A record with this value already exists".to_string(),
                );
            }
        }
        log::error!("Database error: {:?}", err);
        AppError::DatabaseError(err.to_string())
    }
}

/// Convert r2d2 pool errors to AppError
impl From<r2d2::Error> for AppError {
    fn from(err: r2d2::Error) -> Self {
        log::error!("Connection pool error: {:?}", err);
        AppError::DatabaseError(format!("Connection pool error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            AppError::NotFound("test".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::ValidationError("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::DuplicateCode("test".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::ExpiredUrl("test".into()).status_code(),
            StatusCode::GONE
        );
        assert_eq!(
            AppError::DatabaseError("test".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::InternalError("test".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Forbidden("test".into()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::EmailAlreadyExists("test".into()).status_code(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn test_error_display() {
        let err = AppError::NotFound("URL not found".into());
        assert!(err.to_string().contains("Not found"));
    }

    #[test]
    fn test_all_error_variants_have_responses() {
        // Ensure all error variants produce valid HTTP responses
        let errors = vec![
            AppError::NotFound("test".into()),
            AppError::ValidationError("test".into()),
            AppError::DatabaseError("test".into()),
            AppError::DuplicateCode("test".into()),
            AppError::ExpiredUrl("test".into()),
            AppError::InternalError("test".into()),
            AppError::Unauthorized("test".into()),
            AppError::Forbidden("test".into()),
            AppError::EmailAlreadyExists("test".into()),
        ];

        for err in errors {
            let response = err.error_response();
            assert!(response.status().is_client_error() || response.status().is_server_error());
        }
    }

    #[test]
    fn test_constructor_methods() {
        // Test all constructor methods produce correct error types
        assert!(matches!(
            AppError::url_not_found("abc123"),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            AppError::url_not_found_by_id(123),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            AppError::user_not_found(456),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            AppError::tag_not_found(789),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            AppError::url_expired("abc123"),
            AppError::ExpiredUrl(_)
        ));
        assert!(matches!(
            AppError::duplicate_code("test"),
            AppError::DuplicateCode(_)
        ));
        assert!(matches!(
            AppError::invalid_api_key(),
            AppError::Unauthorized(_)
        ));
        assert!(matches!(
            AppError::missing_api_key(),
            AppError::Unauthorized(_)
        ));
        assert!(matches!(
            AppError::not_owner("URL"),
            AppError::Forbidden(_)
        ));
        assert!(matches!(
            AppError::validation("test"),
            AppError::ValidationError(_)
        ));
        assert!(matches!(
            AppError::internal("test"),
            AppError::InternalError(_)
        ));
    }

    #[test]
    fn test_constructor_messages() {
        // Verify constructors produce expected messages
        let err = AppError::url_not_found("abc123");
        assert!(err.to_string().contains("abc123"));

        let err = AppError::url_not_found_by_id(123);
        assert!(err.to_string().contains("123"));

        let err = AppError::duplicate_code("mycode");
        assert!(err.to_string().contains("mycode"));
    }
}
