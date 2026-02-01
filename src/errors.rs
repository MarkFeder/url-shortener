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
        }
    }
}

impl std::error::Error for AppError {}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::DuplicateCode(_) => StatusCode::CONFLICT,
            AppError::ExpiredUrl(_) => StatusCode::GONE,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
        };

        HttpResponse::build(self.status_code()).json(ErrorResponse::new(message, error_code))
    }
}

/// Convert rusqlite errors to AppError
impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
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
    }

    #[test]
    fn test_error_display() {
        let err = AppError::NotFound("URL not found".into());
        assert!(err.to_string().contains("Not found"));
    }
}
