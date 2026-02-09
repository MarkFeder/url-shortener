//! URL endpoint handlers: CRUD, search, stats, QR code.

use actix_web::{delete, get, post, web, HttpResponse};
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::cache::AppCache;
use crate::config::Config;
use crate::constants::{DEFAULT_PAGE_LIMIT, DEFAULT_QR_SIZE, MAX_PAGE_LIMIT, MAX_QR_SIZE, MIN_QR_SIZE};
use crate::db::DbPool;
use crate::errors::AppError;
use crate::metrics::AppMetrics;
use crate::models::{
    CreateUrlRequest, CreateUrlResponse, ListUrlsQuery, MessageResponse, QrCodeQuery,
    SearchUrlsQuery, UrlListResponse, UrlResponse,
};
use crate::qr::{self, QrFormat, QrOptions};
use crate::services;

/// Create a new short URL
#[post("/shorten")]
pub(super) async fn create_short_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    metrics: Option<web::Data<AppMetrics>>,
    body: web::Json<CreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    url::Url::parse(&body.url)
        .map_err(|_| AppError::ValidationError("Invalid URL format".into()))?;

    let url = services::create_url_with_metrics(
        &pool,
        &body,
        config.short_code_length,
        user.user_id,
        metrics.as_ref().map(|m| m.as_ref()),
    )?;

    let response = CreateUrlResponse {
        short_code: url.short_code.clone(),
        short_url: format!("{}/{}", config.base_url, url.short_code),
        original_url: url.original_url,
        created_at: url.created_at,
        expires_at: url.expires_at,
    };

    Ok(HttpResponse::Created().json(response))
}

/// Search URLs by original URL and/or short code
#[get("/urls/search")]
pub(super) async fn search_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    query: web::Query<SearchUrlsQuery>,
) -> Result<HttpResponse, AppError> {
    if query.q.is_none() && query.code.is_none() {
        return Err(AppError::ValidationError(
            "At least one search parameter (q or code) is required".into(),
        ));
    }

    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);

    let urls = services::search_urls(
        &pool,
        user.user_id,
        query.q.as_deref(),
        query.code.as_deref(),
        limit,
    )?;

    let url_responses: Vec<UrlResponse> = urls
        .into_iter()
        .map(|u| UrlResponse::from_url(u, &config.base_url))
        .collect();

    let response = UrlListResponse {
        total: url_responses.len(),
        urls: url_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// List all URLs for the authenticated user with pagination
#[get("/urls")]
pub(super) async fn list_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    query: web::Query<ListUrlsQuery>,
) -> Result<HttpResponse, AppError> {
    let urls = services::list_urls(&pool, user.user_id, &query)?;
    let total = services::count_urls(&pool, user.user_id)?;

    let url_responses: Vec<UrlResponse> = urls
        .into_iter()
        .map(|u| UrlResponse::from_url(u, &config.base_url))
        .collect();

    let response = UrlListResponse {
        total,
        urls: url_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get URL details by ID
#[get("/urls/{id}")]
pub(super) async fn get_url_by_id(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    let url = services::get_url_by_id(&pool, id, user.user_id)?;
    let response = UrlResponse::from_url(url, &config.base_url);

    Ok(HttpResponse::Ok().json(response))
}

/// Get URL statistics and recent clicks
#[get("/urls/{id}/stats")]
pub(super) async fn get_url_stats(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    let url = services::get_url_by_id(&pool, id, user.user_id)?;
    let click_logs = services::get_click_logs(&pool, id, 50)?;

    let response = serde_json::json!({
        "url": UrlResponse::from_url(url, &config.base_url),
        "recent_clicks": click_logs
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Get QR code for a URL
#[get("/urls/{id}/qr")]
pub(super) async fn get_url_qr_code(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
    query: web::Query<QrCodeQuery>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();

    let url = services::get_url_by_id(&pool, id, user.user_id)?;

    let short_url = format!("{}/{}", config.base_url, url.short_code);

    let format = query
        .format
        .as_ref()
        .map(|f| QrFormat::from_str(f))
        .unwrap_or_default();

    let size = query.size.unwrap_or(DEFAULT_QR_SIZE).clamp(MIN_QR_SIZE, MAX_QR_SIZE);

    let options = QrOptions { format, size };

    let qr_bytes = qr::generate_qr_code(&short_url, &options)?;

    Ok(HttpResponse::Ok()
        .content_type(format.content_type())
        .body(qr_bytes))
}

/// Delete a URL by ID
#[delete("/urls/{id}")]
pub(super) async fn delete_url_by_id(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::delete_url_with_cache(&pool, Some(&cache), id, user.user_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("URL deleted successfully")))
}
