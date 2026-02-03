//! HTTP request handlers for the URL shortener API.
//!
//! Defines all route handlers and configures the routing table.

use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::config::Config;
use crate::db::DbPool;
use crate::errors::AppError;
use crate::models::{
    ApiKeyListResponse, ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse,
    CreateUrlRequest, CreateUrlResponse, ListUrlsQuery, MessageResponse, RegisterRequest,
    RegisterResponse, UrlListResponse, UrlResponse,
};
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
            // URL routes (all protected)
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
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let key_id = path.into_inner();
    services::revoke_api_key(&pool, user.user_id, key_id)?;

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
    body: web::Json<CreateUrlRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    body.validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid input: {}", e)))?;

    // Validate URL format
    url::Url::parse(&body.url)
        .map_err(|_| AppError::ValidationError("Invalid URL format".into()))?;

    // Create the short URL
    let url = services::create_url(&pool, &body, config.short_code_length, user.user_id)?;

    let response = CreateUrlResponse {
        short_code: url.short_code.clone(),
        short_url: format!("{}/{}", config.base_url, url.short_code),
        original_url: url.original_url,
        created_at: url.created_at,
        expires_at: url.expires_at,
    };

    Ok(HttpResponse::Created().json(response))
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
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let id = path.into_inner();
    services::delete_url(&pool, id, user.user_id)?;

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
}
