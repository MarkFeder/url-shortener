//! HTTP request handlers for the URL shortener API.
//!
//! Defines all route handlers and configures the routing table.

use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use validator::Validate;

use crate::config::Config;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{
    CreateUrlRequest, CreateUrlResponse, ListUrlsQuery, MessageResponse, UrlListResponse,
    UrlResponse,
};
use crate::services;

/// Configure all application routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(create_short_url)
            .service(list_urls)
            .service(get_url_by_id)
            .service(delete_url_by_id)
            .service(get_url_stats),
    )
    // Register specific routes before catch-all route
    .service(health_check)
    .service(redirect_to_url);
}

// ============================================================================
// API Endpoints
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
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    body: web::Json<CreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    // Validate URL format
    url::Url::parse(&body.url)
        .map_err(|_| AppError::ValidationError("Invalid URL format".into()))?;

    // Create the short URL
    let url = services::create_url(&pool, &body, config.short_code_length)?;

    let response = CreateUrlResponse {
        short_code: url.short_code.clone(),
        short_url: format!("{}/{}", config.base_url, url.short_code),
        original_url: url.original_url,
        created_at: url.created_at,
        expires_at: url.expires_at,
    };

    Ok(HttpResponse::Created().json(response))
}

/// List all URLs with pagination
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
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    query: web::Query<ListUrlsQuery>,
) -> Result<HttpResponse, AppError> {
    let urls = services::list_urls(&pool, &query)?;
    let total = services::count_urls(&pool)?;

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
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    let url = services::get_url_by_id(&pool, id)?;
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
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    let url = services::get_url_by_id(&pool, id)?;
    let click_logs = services::get_click_logs(&pool, id, 50)?;

    let response = serde_json::json!({
        "url": UrlResponse::from_url(url, &config.base_url),
        "recent_clicks": click_logs
    });

    Ok(HttpResponse::Ok().json(response))
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
    pool: web::Data<DbPool>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::delete_url(&pool, id)?;

    Ok(HttpResponse::Ok().json(MessageResponse::new("URL deleted successfully")))
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
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let short_code = path.into_inner();

    // Don't redirect for common paths
    if short_code == "favicon.ico" || short_code == "robots.txt" {
        return Err(AppError::NotFound("Resource not found".into()));
    }

    let url = services::get_url_by_code(&pool, &short_code)?;

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
    use actix_web::{test, App};
    use crate::db::{init_pool, run_migrations};

    async fn setup_test_app() -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        // Use shared cache mode so all connections share the same in-memory database
        let pool = init_pool("file::memory:?cache=shared").unwrap();
        run_migrations(&pool).unwrap();
        let config = Config::default();

        test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(config))
                .configure(configure_routes),
        )
        .await
    }

    #[actix_rt::test]
    async fn test_health_check() {
        let app = setup_test_app().await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_create_and_redirect() {
        let app = setup_test_app().await;

        // Create a short URL
        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .set_json(serde_json::json!({
                "url": "https://example.com",
                "custom_code": "test"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);

        // Test redirect
        let req = test::TestRequest::get().uri("/test").to_request();
        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 301);
    }

    #[actix_rt::test]
    async fn test_invalid_url() {
        let app = setup_test_app().await;

        let req = test::TestRequest::post()
            .uri("/api/shorten")
            .set_json(serde_json::json!({
                "url": "not-a-valid-url"
            }))
            .to_request();

        let resp: actix_web::dev::ServiceResponse = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400);
    }
}
