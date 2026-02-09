//! Bulk URL operation endpoint handlers.

use actix_web::{delete, post, web, HttpResponse};
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::cache::AppCache;
use crate::config::Config;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{BulkCreateUrlRequest, BulkDeleteUrlRequest, BulkOperationStatus};
use crate::services;

/// Bulk create multiple short URLs
#[post("/urls/bulk")]
pub(super) async fn bulk_create_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    body: web::Json<BulkCreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    // Validate each URL format
    for (index, item) in body.urls.iter().enumerate() {
        url::Url::parse(&item.url).map_err(|_| {
            AppError::ValidationError(format!("Invalid URL format at index {}", index))
        })?;
    }

    let response = services::bulk_create_urls(
        &pool,
        &body.urls,
        config.short_code_length,
        user.user_id,
        &config.base_url,
    )?;

    let status_code = if response.status == BulkOperationStatus::Success {
        actix_web::http::StatusCode::CREATED
    } else {
        actix_web::http::StatusCode::MULTI_STATUS
    };

    Ok(HttpResponse::build(status_code).json(response))
}

/// Bulk delete multiple URLs by ID
#[delete("/urls/bulk")]
pub(super) async fn bulk_delete_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    body: web::Json<BulkDeleteUrlRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    let response = services::bulk_delete_urls_with_cache(&pool, Some(&cache), &body.ids, user.user_id)?;

    let status_code = if response.status == BulkOperationStatus::Success {
        actix_web::http::StatusCode::OK
    } else {
        actix_web::http::StatusCode::MULTI_STATUS
    };

    Ok(HttpResponse::build(status_code).json(response))
}
