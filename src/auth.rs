//! API key authentication module.
//!
//! Provides an extractor for validating API keys on protected endpoints.

use actix_web::{dev::Payload, web, FromRequest, HttpRequest};
use std::future::{ready, Ready};

use crate::config::Config;
use crate::errors::AppError;

/// API key extractor for protecting endpoints.
///
/// Add this to handler parameters to require authentication.
/// The key can be provided via:
/// - `Authorization: Bearer <key>` header
/// - `X-API-Key: <key>` header
///
/// If no API key is configured in the environment, all requests are allowed.
pub struct ApiKey;

impl FromRequest for ApiKey {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Get the config from app data
        let config = match req.app_data::<web::Data<Config>>() {
            Some(config) => config,
            None => {
                return ready(Err(AppError::InternalError(
                    "Configuration not available".into(),
                )));
            }
        };

        // If no API key is configured, allow all requests
        let expected_key = match &config.api_key {
            Some(key) => key,
            None => return ready(Ok(ApiKey)),
        };

        // Try to extract the API key from headers
        let provided_key = extract_api_key(req);

        match provided_key {
            Some(key) if key == expected_key => ready(Ok(ApiKey)),
            Some(_) => ready(Err(AppError::Unauthorized("Invalid API key".into()))),
            None => ready(Err(AppError::Unauthorized(
                "Missing API key. Provide via 'Authorization: Bearer <key>' or 'X-API-Key: <key>' header".into(),
            ))),
        }
    }
}

/// Extract API key from request headers.
///
/// Checks both `Authorization: Bearer <key>` and `X-API-Key: <key>` headers.
fn extract_api_key(req: &HttpRequest) -> Option<&str> {
    // Try Authorization: Bearer <key>
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(key) = auth_str.strip_prefix("Bearer ") {
                return Some(key.trim());
            }
        }
    }

    // Try X-API-Key header
    if let Some(api_key_header) = req.headers().get("X-API-Key") {
        if let Ok(key) = api_key_header.to_str() {
            return Some(key.trim());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    async fn protected_endpoint(_key: ApiKey) -> HttpResponse {
        HttpResponse::Ok().body("success")
    }

    #[actix_rt::test]
    async fn test_no_api_key_configured_allows_all() {
        let config = Config::default(); // api_key is None

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/protected").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_valid_bearer_token() {
        let mut config = Config::default();
        config.api_key = Some("test-key".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Bearer test-key"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_valid_x_api_key_header() {
        let mut config = Config::default();
        config.api_key = Some("test-key".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("X-API-Key", "test-key"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_missing_api_key_returns_401() {
        let mut config = Config::default();
        config.api_key = Some("test-key".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/protected").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_invalid_api_key_returns_401() {
        let mut config = Config::default();
        config.api_key = Some("test-key".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(config))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("X-API-Key", "wrong-key"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }
}
