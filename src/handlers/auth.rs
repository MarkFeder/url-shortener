//! Auth endpoint handlers: registration and API key management.

use actix_web::{delete, get, post, web, HttpResponse};
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::cache::AppCache;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{
    ApiKeyListResponse, ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse,
    MessageResponse, RegisterRequest, RegisterResponse,
};
use crate::services;

/// Register a new user
#[post("/register")]
pub(super) async fn register(
    pool: web::Data<DbPool>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    let (user, api_key) = services::register_user(&pool, &body.email)?;

    let response = RegisterResponse {
        user_id: user.id,
        email: user.email,
        api_key,
    };

    Ok(HttpResponse::Created().json(response))
}

/// Create a new API key
#[post("/keys")]
pub(super) async fn create_api_key(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    body: web::Json<CreateApiKeyRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    let (record, api_key) = services::create_api_key(&pool, user.user_id, &body.name)?;

    let response = CreateApiKeyResponse {
        id: record.id,
        name: record.name,
        api_key,
        created_at: record.created_at,
    };

    Ok(HttpResponse::Created().json(response))
}

/// List all API keys for the authenticated user
#[get("/keys")]
pub(super) async fn list_api_keys(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, AppError> {
    let keys = services::list_api_keys(&pool, user.user_id)?;

    let key_responses: Vec<ApiKeyResponse> = keys.iter().map(ApiKeyResponse::from_record).collect();

    let response = ApiKeyListResponse {
        keys: key_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Revoke an API key
#[delete("/keys/{id}")]
pub(super) async fn revoke_api_key(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let key_id = path.into_inner();
    services::revoke_api_key_with_cache(&pool, Some(&cache), user.user_id, key_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("API key revoked successfully")))
}
