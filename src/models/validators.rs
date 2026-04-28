//! Custom validators shared by request DTOs.

use validator::ValidationError;

/// Custom validator for positive hours values
pub(super) fn validate_positive_hours(hours: i64) -> Result<(), ValidationError> {
    if hours <= 0 {
        return Err(ValidationError::new(
            "expires_in_hours must be a positive number",
        ));
    }
    Ok(())
}

/// Custom validator for alphanumeric codes (letters, numbers, underscore, hyphen)
pub(super) fn validate_alphanumeric(code: &str) -> Result<(), ValidationError> {
    lazy_static::lazy_static! {
        static ref ALPHANUMERIC_REGEX: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    }
    if ALPHANUMERIC_REGEX.is_match(code) {
        Ok(())
    } else {
        Err(ValidationError::new(
            "Custom code must be alphanumeric (letters, numbers, underscore, hyphen)",
        ))
    }
}
