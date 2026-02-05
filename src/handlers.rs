//! HTTP request handlers for the URL shortener API.
//!
//! Defines all route handlers and configures the routing table.

use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::cache::AppCache;
use crate::config::Config;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::metrics::AppMetrics;
use crate::models::{
    AddTagToUrlRequest, ApiKeyListResponse, ApiKeyResponse, BulkCreateUrlRequest,
    BulkDeleteUrlRequest, BulkOperationStatus, CreateApiKeyRequest, CreateApiKeyResponse,
    CreateTagRequest, CreateUrlRequest, CreateUrlResponse, ListUrlsQuery, MessageResponse,
    QrCodeQuery, RegisterRequest, RegisterResponse, SearchUrlsQuery, TagListResponse,
    TagResponse, UrlListResponse, UrlResponse, UrlWithTagsResponse, UrlsByTagResponse,
};
use crate::qr::{self, QrFormat, QrOptions};
use crate::services;

/// Configure all application routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // Auth routes (register is public)
            .service(
                web::scope("/auth")
                    .service(register)
                    .service(create_api_key)
                    .service(list_api_keys)
                    .service(revoke_api_key),
            )
            // Tag routes
            .service(create_tag)
            .service(list_tags)
            .service(delete_tag)
            .service(get_urls_by_tag)
            .service(add_tag_to_url)
            .service(remove_tag_from_url)
            // Bulk URL operations (must be registered before single-item routes)
            .service(bulk_create_urls)
            .service(bulk_delete_urls)
            // URL routes (all protected)
            .service(create_short_url)
            .service(search_urls)
            .service(list_urls)
            .service(get_url_by_id)
            .service(delete_url_by_id)
            .service(get_url_stats)
            .service(get_url_qr_code),
    )
    // Register specific routes before catch-all route
    .service(health_check)
    .service(redirect_to_url);
}

// ============================================================================
// Auth Endpoints
// ============================================================================

/// Register a new user
///
/// # Request Body
/// ```json
/// {
///     "email": "user@example.com"
/// }
/// ```
///
/// # Response
/// ```json
/// {
///     "user_id": 1,
///     "email": "user@example.com",
///     "api_key": "usk_..."
/// }
/// ```
#[post("/register")]
async fn register(
    pool: web::Data<DbPool>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
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
///
/// # Request Body
/// ```json
/// {
///     "name": "CI/CD key"
/// }
/// ```
///
/// # Response
/// ```json
/// {
///     "id": 2,
///     "name": "CI/CD key",
///     "api_key": "usk_...",
///     "created_at": "2024-01-01 12:00:00"
/// }
/// ```
#[post("/keys")]
async fn create_api_key(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    body: web::Json<CreateApiKeyRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
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
///
/// # Response
/// ```json
/// {
///     "keys": [
///         {
///             "id": 1,
///             "name": "Default key",
///             "created_at": "2024-01-01 12:00:00",
///             "last_used_at": "2024-01-02 12:00:00",
///             "is_active": true
///         }
///     ]
/// }
/// ```
#[get("/keys")]
async fn list_api_keys(
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
///
/// # Path Parameters
/// - `id`: The API key ID to revoke
///
/// # Response
/// ```json
/// {
///     "message": "API key revoked successfully"
/// }
/// ```
#[delete("/keys/{id}")]
async fn revoke_api_key(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let key_id = path.into_inner();
    services::revoke_api_key_with_cache(&pool, Some(&cache), user.user_id, key_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("API key revoked successfully")))
}

// ============================================================================
// URL Endpoints
// ============================================================================

/// Create a new short URL
///
/// # Request Body
/// ```json
/// {
///     "url": "https://example.com/very/long/url",
///     "custom_code": "mylink",  // optional
///     "expires_in_hours": 24    // optional
/// }
/// ```
///
/// # Response
/// ```json
/// {
///     "short_code": "mylink",
///     "short_url": "http://localhost:8080/mylink",
///     "original_url": "https://example.com/very/long/url",
///     "created_at": "2024-01-01 12:00:00",
///     "expires_at": null
/// }
/// ```
#[post("/shorten")]
async fn create_short_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    metrics: Option<web::Data<AppMetrics>>,
    body: web::Json<CreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    // Validate URL format
    url::Url::parse(&body.url)
        .map_err(|_| AppError::ValidationError("Invalid URL format".into()))?;

    // Create the short URL with metrics
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
///
/// # Query Parameters
/// - `q`: Search term for original URL (case-insensitive, partial match)
/// - `code`: Search term for short code (case-insensitive, partial match)
/// - `limit`: Maximum results (default: 20, max: 100)
///
/// At least one of `q` or `code` must be provided.
///
/// # Response
/// ```json
/// {
///     "total": 5,
///     "urls": [...]
/// }
/// ```
#[get("/urls/search")]
async fn search_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    query: web::Query<SearchUrlsQuery>,
) -> Result<HttpResponse, AppError> {
    // Validate that at least one search parameter is provided
    if query.q.is_none() && query.code.is_none() {
        return Err(AppError::ValidationError(
            "At least one search parameter (q or code) is required".into(),
        ));
    }

    let limit = query.limit.unwrap_or(20).min(100);

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
///
/// # Query Parameters
/// - `page`: Page number (default: 1)
/// - `limit`: Items per page (default: 20, max: 100)
/// - `sort`: Sort order - "asc" or "desc" (default: "desc")
///
/// # Response
/// ```json
/// {
///     "total": 42,
///     "urls": [...]
/// }
/// ```
#[get("/urls")]
async fn list_urls(
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
///
/// # Path Parameters
/// - `id`: The URL ID
///
/// # Response
/// Returns the full URL details including click statistics
#[get("/urls/{id}")]
async fn get_url_by_id(
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
///
/// # Path Parameters
/// - `id`: The URL ID
///
/// # Response
/// Returns click statistics and recent click logs
#[get("/urls/{id}/stats")]
async fn get_url_stats(
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
///
/// # Path Parameters
/// - `id`: The URL ID
///
/// # Query Parameters
/// - `format`: Output format - "png" (default) or "svg"
/// - `size`: Size in pixels (default: 256, min: 64, max: 1024)
///
/// # Response
/// Returns the QR code image in the requested format
#[get("/urls/{id}/qr")]
async fn get_url_qr_code(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
    query: web::Query<QrCodeQuery>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();

    // Verify the URL exists and belongs to the user
    let url = services::get_url_by_id(&pool, id, user.user_id)?;

    // Build the full short URL
    let short_url = format!("{}/{}", config.base_url, url.short_code);

    // Parse and validate options
    let format = query
        .format
        .as_ref()
        .map(|f| QrFormat::from_str(f))
        .unwrap_or_default();

    let size = query.size.unwrap_or(256).clamp(64, 1024);

    let options = QrOptions { format, size };

    // Generate QR code
    let qr_bytes = qr::generate_qr_code(&short_url, &options)?;

    Ok(HttpResponse::Ok()
        .content_type(format.content_type())
        .body(qr_bytes))
}

/// Delete a URL by ID
///
/// # Path Parameters
/// - `id`: The URL ID to delete
///
/// # Response
/// ```json
/// {
///     "message": "URL deleted successfully"
/// }
/// ```
#[delete("/urls/{id}")]
async fn delete_url_by_id(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::delete_url_with_cache(&pool, Some(&cache), id, user.user_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("URL deleted successfully")))
}

// ============================================================================
// Bulk URL Endpoints
// ============================================================================

/// Bulk create multiple short URLs
///
/// # Request Body
/// ```json
/// {
///     "urls": [
///         { "url": "https://example1.com", "custom_code": "ex1" },
///         { "url": "https://example2.com", "expires_in_hours": 24 }
///     ]
/// }
/// ```
///
/// # Response
/// - 201 Created: All items succeeded
/// - 207 Multi-Status: Partial success or all failed (check response body)
///
/// ```json
/// {
///     "status": "success",
///     "total": 2,
///     "succeeded": 2,
///     "failed": 0,
///     "results": [...]
/// }
/// ```
#[post("/urls/bulk")]
async fn bulk_create_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    body: web::Json<BulkCreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    // Validate each URL format
    for (index, item) in body.urls.iter().enumerate() {
        url::Url::parse(&item.url).map_err(|_| {
            AppError::ValidationError(format!("Invalid URL format at index {}", index))
        })?;
    }

    // Perform bulk create
    let response = services::bulk_create_urls(
        &pool,
        &body.urls,
        config.short_code_length,
        user.user_id,
        &config.base_url,
    )?;

    // Return appropriate status code based on results
    let status_code = if response.status == BulkOperationStatus::Success {
        actix_web::http::StatusCode::CREATED
    } else {
        actix_web::http::StatusCode::MULTI_STATUS
    };

    Ok(HttpResponse::build(status_code).json(response))
}

/// Bulk delete multiple URLs by ID
///
/// # Request Body
/// ```json
/// {
///     "ids": [1, 2, 3]
/// }
/// ```
///
/// # Response
/// - 200 OK: All items succeeded
/// - 207 Multi-Status: Partial success or all failed (check response body)
///
/// ```json
/// {
///     "status": "success",
///     "total": 3,
///     "succeeded": 3,
///     "failed": 0,
///     "results": [...]
/// }
/// ```
#[delete("/urls/bulk")]
async fn bulk_delete_urls(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    body: web::Json<BulkDeleteUrlRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    // Perform bulk delete with cache invalidation
    let response = services::bulk_delete_urls_with_cache(&pool, Some(&cache), &body.ids, user.user_id)?;

    // Return appropriate status code based on results
    let status_code = if response.status == BulkOperationStatus::Success {
        actix_web::http::StatusCode::OK
    } else {
        actix_web::http::StatusCode::MULTI_STATUS
    };

    Ok(HttpResponse::build(status_code).json(response))
}

// ============================================================================
// Tag Endpoints
// ============================================================================

/// Create a new tag
///
/// # Request Body
/// ```json
/// {
///     "name": "Important"
/// }
/// ```
///
/// # Response
/// ```json
/// {
///     "id": 1,
///     "name": "Important",
///     "created_at": "2024-01-01 12:00:00"
/// }
/// ```
#[post("/tags")]
async fn create_tag(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    body: web::Json<CreateTagRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    let tag = services::create_tag(&pool, &body.name, user.user_id)?;

    let response = TagResponse::from_tag(&tag);
    Ok(HttpResponse::Created().json(response))
}

/// List all tags for the authenticated user
///
/// # Response
/// ```json
/// {
///     "tags": [
///         { "id": 1, "name": "Important", "created_at": "..." },
///         { "id": 2, "name": "Work", "created_at": "..." }
///     ]
/// }
/// ```
#[get("/tags")]
async fn list_tags(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, AppError> {
    let tags = services::list_tags(&pool, user.user_id)?;

    let tag_responses: Vec<TagResponse> = tags.iter().map(TagResponse::from_tag).collect();

    let response = TagListResponse {
        tags: tag_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Delete a tag
///
/// # Path Parameters
/// - `id`: The tag ID to delete
///
/// # Response
/// ```json
/// {
///     "message": "Tag deleted successfully"
/// }
/// ```
#[delete("/tags/{id}")]
async fn delete_tag(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let tag_id = path.into_inner();
    services::delete_tag(&pool, tag_id, user.user_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("Tag deleted successfully")))
}

/// Add a tag to a URL
///
/// # Path Parameters
/// - `id`: The URL ID
///
/// # Request Body
/// ```json
/// {
///     "tag_id": 1
/// }
/// ```
///
/// # Response
/// ```json
/// {
///     "message": "Tag added to URL successfully"
/// }
/// ```
#[post("/urls/{id}/tags")]
async fn add_tag_to_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
    body: web::Json<AddTagToUrlRequest>,
) -> Result<HttpResponse, AppError> {
    let url_id = path.into_inner();
    services::add_tag_to_url(&pool, url_id, body.tag_id, user.user_id)?;

    Ok(HttpResponse::Created().json(MessageResponse::new("Tag added to URL successfully")))
}

/// Remove a tag from a URL
///
/// # Path Parameters
/// - `id`: The URL ID
/// - `tag_id`: The tag ID to remove
///
/// # Response
/// ```json
/// {
///     "message": "Tag removed from URL successfully"
/// }
/// ```
#[delete("/urls/{id}/tags/{tag_id}")]
async fn remove_tag_from_url(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    path: web::Path<(i64, i64)>,
) -> Result<HttpResponse, AppError> {
    let (url_id, tag_id) = path.into_inner();
    services::remove_tag_from_url(&pool, url_id, tag_id, user.user_id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("Tag removed from URL successfully")))
}

/// Get all URLs with a specific tag
///
/// # Path Parameters
/// - `id`: The tag ID
///
/// # Response
/// ```json
/// {
///     "urls": [
///         { "id": 1, "short_code": "abc123", "original_url": "...", "tags": [...] }
///     ]
/// }
/// ```
#[get("/tags/{id}/urls")]
async fn get_urls_by_tag(
    user: AuthenticatedUser,
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let tag_id = path.into_inner();

    // Use optimized function that fetches URLs with their tags in 2 queries instead of N+1
    let urls_with_tags = services::get_urls_by_tag_with_tags(&pool, tag_id, user.user_id)?;

    let url_responses: Vec<UrlWithTagsResponse> = urls_with_tags
        .into_iter()
        .map(|(url, tags)| {
            let tag_responses: Vec<TagResponse> = tags.iter().map(TagResponse::from_tag).collect();
            UrlWithTagsResponse {
                id: url.id,
                short_code: url.short_code.clone(),
                short_url: format!("{}/{}", config.base_url, url.short_code),
                original_url: url.original_url,
                clicks: url.clicks,
                created_at: url.created_at,
                updated_at: url.updated_at,
                expires_at: url.expires_at,
                tags: tag_responses,
            }
        })
        .collect();

    let response = UrlsByTagResponse {
        urls: url_responses,
    };

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// Redirect Endpoint
// ============================================================================

/// Redirect to the original URL
///
/// This is the main functionality - when someone visits /{short_code},
/// they get redirected to the original URL.
///
/// # Path Parameters
/// - `short_code`: The short code to look up
///
/// # Response
/// - 301 Permanent Redirect to the original URL
/// - 404 Not Found if the code doesn't exist
/// - 410 Gone if the URL has expired
#[get("/{short_code}")]
async fn redirect_to_url(
    pool: web::Data<DbPool>,
    cache: web::Data<AppCache>,
    metrics: Option<web::Data<AppMetrics>>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let short_code = path.into_inner();

    // Don't redirect for common paths
    if short_code == "favicon.ico" || short_code == "robots.txt" {
        return Err(AppError::NotFound("Resource not found".into()));
    }

    let url = services::get_url_by_code_cached_with_metrics(
        &pool,
        &cache,
        &short_code,
        metrics.as_ref().map(|m| m.as_ref()),
    )?;

    // Extract request metadata for analytics
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let referer = req
        .headers()
        .get("referer")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Record the click asynchronously (don't block the redirect)
    let _ = services::record_click(
        &pool,
        url.id,
        ip_address.as_deref(),
        user_agent.as_deref(),
        referer.as_deref(),
    );

    // Record redirect metric
    if let Some(ref m) = metrics {
        m.record_redirect();
    }

    log::info!(
        "Redirecting {} -> {} (clicks: {})",
        short_code,
        url.original_url,
        url.clicks + 1
    );

    // Return 301 Moved Permanently redirect
    Ok(HttpResponse::MovedPermanently()
        .append_header(("Location", url.original_url))
        .finish())
}

// ============================================================================
// Health Check
// ============================================================================

/// Health check endpoint
///
/// # Response
/// ```json
/// {
///     "status": "healthy",
///     "version": "0.1.0"
/// }
/// ```
#[get("/health")]
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init_pool, run_migrations};
    use actix_web::{test, App};

    fn setup_test_pool() -> DbPool {
        let pool = init_pool("file::memory:?cache=shared").unwrap();
        run_migrations(&pool).unwrap();
        pool
    }

    async fn setup_test_app(
        pool: DbPool,
    ) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        let config = Config::default();
        let cache = AppCache::default();

        test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(config))
                .app_data(web::Data::new(cache))
                .configure(configure_routes),
        )
        .await
    }

    #[actix_rt::test]
    async fn test_health_check() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_register_user() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(serde_json::json!({
                "email": "test@example.com"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: RegisterResponse = test::read_body_json(resp).await;
        assert_eq!(body.email, "test@example.com");
        assert!(body.api_key.starts_with("usk_"));
    }

    #[actix_rt::test]
    async fn test_create_url_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .set_json(serde_json::json!({
                "url": "https://example.com"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_create_and_list_urls() {
        let pool = setup_test_pool();

        // Register a user first
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Create a short URL
        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .insert_header(("X-API-Key", api_key.clone()))
            .set_json(serde_json::json!({
                "url": "https://example.com",
                "custom_code": "test"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        // List URLs
        let req = test::TestRequest::get()
            .uri("/api/urls")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "test");
    }

    #[actix_rt::test]
    async fn test_redirect() {
        let pool = setup_test_pool();

        // Register a user and create a URL
        let (user, _) = services::register_user(&pool, "test@example.com").unwrap();
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("redirect_test".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Test redirect
        let req = test::TestRequest::get()
            .uri("/redirect_test")
            .to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 301);
    }

    #[actix_rt::test]
    async fn test_api_key_management() {
        let pool = setup_test_pool();

        // Register a user
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Create a new API key
        let req = test::TestRequest::post()
            .uri("/api/auth/keys")
            .insert_header(("X-API-Key", api_key.clone()))
            .set_json(serde_json::json!({
                "name": "Test Key"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: CreateApiKeyResponse = test::read_body_json(resp).await;
        assert_eq!(body.name, "Test Key");

        // List API keys
        let req = test::TestRequest::get()
            .uri("/api/auth/keys")
            .insert_header(("X-API-Key", api_key.clone()))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: ApiKeyListResponse = test::read_body_json(resp).await;
        assert_eq!(body.keys.len(), 2); // Default + Test Key

        // Revoke the new key
        let key_id = body.keys.iter().find(|k| k.name == "Test Key").unwrap().id;

        let req = test::TestRequest::delete()
            .uri(&format!("/api/auth/keys/{}", key_id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_url_ownership_isolation() {
        let pool = setup_test_pool();

        // Register two users
        let (user1, api_key1) = services::register_user(&pool, "user1@example.com").unwrap();
        let (_, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        // Create a URL for user1
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("user1_url".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user1.id).unwrap();

        let app = setup_test_app(pool).await;

        // User1 can access their URL
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}", url.id))
            .insert_header(("X-API-Key", api_key1))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // User2 cannot access user1's URL
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}", url.id))
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ========================================================================
    // Bulk Operation Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_bulk_create_endpoint() {
        let pool = setup_test_pool();

        // Register a user
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Bulk create URLs
        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "urls": [
                    { "url": "https://example1.com", "custom_code": "bulk_e1" },
                    { "url": "https://example2.com", "custom_code": "bulk_e2" }
                ]
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: crate::models::BulkCreateUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, BulkOperationStatus::Success);
        assert_eq!(body.total, 2);
        assert_eq!(body.succeeded, 2);
        assert_eq!(body.failed, 0);
    }

    #[actix_rt::test]
    async fn test_bulk_create_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        // Try bulk create without auth
        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .set_json(serde_json::json!({
                "urls": [
                    { "url": "https://example.com" }
                ]
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_bulk_create_validates_limit() {
        let pool = setup_test_pool();

        // Register a user
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Create request with >100 URLs
        let urls: Vec<serde_json::Value> = (0..101)
            .map(|i| serde_json::json!({ "url": format!("https://example{}.com", i) }))
            .collect();

        let req = test::TestRequest::post()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "urls": urls }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_bulk_delete_endpoint() {
        let pool = setup_test_pool();

        // Register a user and create some URLs
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let mut ids = vec![];
        for i in 0..2 {
            let request = CreateUrlRequest {
                url: format!("https://todelete{}.com", i),
                custom_code: Some(format!("todel{}", i)),
                expires_in_hours: None,
            };
            let url = services::create_url(&pool, &request, 7, user.id).unwrap();
            ids.push(url.id);
        }

        let app = setup_test_app(pool).await;

        // Bulk delete
        let req = test::TestRequest::delete()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "ids": ids }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: crate::models::BulkDeleteUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, BulkOperationStatus::Success);
        assert_eq!(body.total, 2);
        assert_eq!(body.succeeded, 2);
    }

    #[actix_rt::test]
    async fn test_bulk_operations_return_207_on_partial() {
        let pool = setup_test_pool();

        // Register a user
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        // Create one URL
        let request = CreateUrlRequest {
            url: "https://existing.com".to_string(),
            custom_code: Some("exists207".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Bulk delete with one valid, one invalid ID
        let req = test::TestRequest::delete()
            .uri("/api/urls/bulk")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({ "ids": [url.id, 99999] }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 207); // Multi-Status

        let body: crate::models::BulkDeleteUrlResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, BulkOperationStatus::PartialSuccess);
        assert_eq!(body.succeeded, 1);
        assert_eq!(body.failed, 1);
    }

    // ========================================================================
    // Tag Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_create_tag_endpoint() {
        let pool = setup_test_pool();

        // Register a user
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Create a tag
        let req = test::TestRequest::post()
            .uri("/api/tags")
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "name": "Important"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        let body: TagResponse = test::read_body_json(resp).await;
        assert_eq!(body.name, "Important");
    }

    #[actix_rt::test]
    async fn test_list_tags_endpoint() {
        let pool = setup_test_pool();

        // Register a user and create tags
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        services::create_tag(&pool, "Work", user.id).unwrap();
        services::create_tag(&pool, "Personal", user.id).unwrap();

        let app = setup_test_app(pool).await;

        // List tags
        let req = test::TestRequest::get()
            .uri("/api/tags")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: TagListResponse = test::read_body_json(resp).await;
        assert_eq!(body.tags.len(), 2);
    }

    #[actix_rt::test]
    async fn test_delete_tag_endpoint() {
        let pool = setup_test_pool();

        // Register a user and create a tag
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        let tag = services::create_tag(&pool, "ToDelete", user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Delete the tag
        let req = test::TestRequest::delete()
            .uri(&format!("/api/tags/{}", tag.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_add_tag_to_url_endpoint() {
        let pool = setup_test_pool();

        // Register a user, create a tag, and create a URL
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        let tag = services::create_tag(&pool, "Important", user.id).unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("tag_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Add tag to URL
        let req = test::TestRequest::post()
            .uri(&format!("/api/urls/{}/tags", url.id))
            .insert_header(("X-API-Key", api_key))
            .set_json(serde_json::json!({
                "tag_id": tag.id
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
    }

    #[actix_rt::test]
    async fn test_tag_endpoints_require_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        // Try to create tag without auth
        let req = test::TestRequest::post()
            .uri("/api/tags")
            .set_json(serde_json::json!({
                "name": "Test"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);

        // Try to list tags without auth
        let req = test::TestRequest::get().uri("/api/tags").to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_get_urls_by_tag_endpoint() {
        let pool = setup_test_pool();

        // Register a user, create a tag, and create URLs
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();
        let tag = services::create_tag(&pool, "Work", user.id).unwrap();

        let request1 = CreateUrlRequest {
            url: "https://work1.com".to_string(),
            custom_code: Some("bytag1".to_string()),
            expires_in_hours: None,
        };
        let url1 = services::create_url(&pool, &request1, 7, user.id).unwrap();
        services::add_tag_to_url(&pool, url1.id, tag.id, user.id).unwrap();

        let request2 = CreateUrlRequest {
            url: "https://work2.com".to_string(),
            custom_code: Some("bytag2".to_string()),
            expires_in_hours: None,
        };
        let url2 = services::create_url(&pool, &request2, 7, user.id).unwrap();
        services::add_tag_to_url(&pool, url2.id, tag.id, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Get URLs by tag
        let req = test::TestRequest::get()
            .uri(&format!("/api/tags/{}/urls", tag.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlsByTagResponse = test::read_body_json(resp).await;
        assert_eq!(body.urls.len(), 2);
    }

    // ========================================================================
    // QR Code Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_get_qr_code_png() {
        let pool = setup_test_pool();

        // Register a user and create a URL
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Get QR code as PNG (default)
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Check content type
        let content_type = resp.headers().get("content-type").unwrap();
        assert_eq!(content_type, "image/png");

        // Check that body contains PNG magic bytes
        let body = test::read_body(resp).await;
        assert!(body.starts_with(&[0x89, 0x50, 0x4E, 0x47]));
    }

    #[actix_rt::test]
    async fn test_get_qr_code_svg() {
        let pool = setup_test_pool();

        // Register a user and create a URL
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_svg_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Get QR code as SVG
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr?format=svg", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Check content type
        let content_type = resp.headers().get("content-type").unwrap();
        assert_eq!(content_type, "image/svg+xml");

        // Check that body contains SVG content
        let body = test::read_body(resp).await;
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("<svg"));
    }

    #[actix_rt::test]
    async fn test_get_qr_code_with_size() {
        let pool = setup_test_pool();

        // Register a user and create a URL
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_size_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Get QR code with custom size
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr?size=512", url.id))
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_get_qr_code_requires_auth() {
        let pool = setup_test_pool();

        // Register a user and create a URL
        let (user, _) = services::register_user(&pool, "test@example.com").unwrap();

        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_auth_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user.id).unwrap();

        let app = setup_test_app(pool).await;

        // Try to get QR code without auth
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr", url.id))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_get_qr_code_not_found() {
        let pool = setup_test_pool();

        // Register a user
        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Try to get QR code for non-existent URL
        let req = test::TestRequest::get()
            .uri("/api/urls/99999/qr")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    #[actix_rt::test]
    async fn test_get_qr_code_respects_ownership() {
        let pool = setup_test_pool();

        // Register two users
        let (user1, _) = services::register_user(&pool, "user1@example.com").unwrap();
        let (_, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        // Create URL owned by user1
        let request = CreateUrlRequest {
            url: "https://example.com".to_string(),
            custom_code: Some("qr_owner_test".to_string()),
            expires_in_hours: None,
        };
        let url = services::create_url(&pool, &request, 7, user1.id).unwrap();

        let app = setup_test_app(pool).await;

        // User2 tries to get QR code for user1's URL
        let req = test::TestRequest::get()
            .uri(&format!("/api/urls/{}/qr", url.id))
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }

    // ========================================================================
    // Search Handler Tests
    // ========================================================================

    #[actix_rt::test]
    async fn test_search_urls_by_original_url() {
        let pool = setup_test_pool();

        // Register a user and create URLs
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let urls_data = [
            ("https://github.com/rust", "gh1"),
            ("https://github.com/tokio", "gh2"),
            ("https://docs.rs/actix", "docs"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            services::create_url(&pool, &request, 7, user.id).unwrap();
        }

        let app = setup_test_app(pool).await;

        // Search for "github"
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=github")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 2);
    }

    #[actix_rt::test]
    async fn test_search_urls_by_short_code() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let urls_data = [
            ("https://example1.com", "proj-alpha"),
            ("https://example2.com", "proj-beta"),
            ("https://example3.com", "docs-main"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            services::create_url(&pool, &request, 7, user.id).unwrap();
        }

        let app = setup_test_app(pool).await;

        // Search for "proj" in code
        let req = test::TestRequest::get()
            .uri("/api/urls/search?code=proj")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 2);
    }

    #[actix_rt::test]
    async fn test_search_urls_combined_filters() {
        let pool = setup_test_pool();

        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let urls_data = [
            ("https://github.com/project", "gh-proj"),
            ("https://github.com/other", "gh-other"),
            ("https://gitlab.com/project", "gl-proj"),
        ];

        for (url, code) in urls_data {
            let request = CreateUrlRequest {
                url: url.to_string(),
                custom_code: Some(code.to_string()),
                expires_in_hours: None,
            };
            services::create_url(&pool, &request, 7, user.id).unwrap();
        }

        let app = setup_test_app(pool).await;

        // Search for github URLs with "proj" in code
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=github&code=proj")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "gh-proj");
    }

    #[actix_rt::test]
    async fn test_search_urls_requires_parameter() {
        let pool = setup_test_pool();

        let (_, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = setup_test_app(pool).await;

        // Search without any parameters should fail
        let req = test::TestRequest::get()
            .uri("/api/urls/search")
            .insert_header(("X-API-Key", api_key))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_rt::test]
    async fn test_search_urls_requires_auth() {
        let pool = setup_test_pool();
        let app = setup_test_app(pool).await;

        // Search without auth should fail
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=test")
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_search_urls_respects_ownership() {
        let pool = setup_test_pool();

        let (user1, api_key1) = services::register_user(&pool, "user1@example.com").unwrap();
        let (user2, api_key2) = services::register_user(&pool, "user2@example.com").unwrap();

        // Create URL for user1
        let request = CreateUrlRequest {
            url: "https://secret.example.com".to_string(),
            custom_code: Some("secret1".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user1.id).unwrap();

        // Create URL for user2
        let request = CreateUrlRequest {
            url: "https://secret.example.com".to_string(),
            custom_code: Some("secret2".to_string()),
            expires_in_hours: None,
        };
        services::create_url(&pool, &request, 7, user2.id).unwrap();

        let app = setup_test_app(pool).await;

        // User1 searches - should only see their URL
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=secret")
            .insert_header(("X-API-Key", api_key1))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "secret1");

        // User2 searches - should only see their URL
        let req = test::TestRequest::get()
            .uri("/api/urls/search?q=secret")
            .insert_header(("X-API-Key", api_key2))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        let body: UrlListResponse = test::read_body_json(resp).await;
        assert_eq!(body.total, 1);
        assert_eq!(body.urls[0].short_code, "secret2");
    }
}
