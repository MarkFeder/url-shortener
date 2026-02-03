//! API key authentication module.
//!
//! Provides an extractor for validating API keys on protected endpoints.

use actix_web::{dev::Payload, web, FromRequest, HttpRequest};
use std::future::{ready, Ready};

use crate::db::DbPool;
use crate::errors::AppError;
use crate::services;

/// Authenticated user extractor for protecting endpoints.
///
/// Add this to handler parameters to require authentication.
/// The key can be provided via:
/// - `Authorization: Bearer <key>` header
/// - `X-API-Key: <key>` header
///
/// On successful authentication, provides the user_id for ownership checks.
pub struct AuthenticatedUser {
    pub user_id: i64,
}

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Get the database pool from app data
        let pool = match req.app_data::<web::Data<DbPool>>() {
            Some(pool) => pool,
            None => {
                return ready(Err(AppError::InternalError(
                    "Database pool not available".into(),
                )));
            }
        };

        // Try to extract the API key from headers
        let provided_key = match extract_api_key(req) {
            Some(key) => key.to_string(),
            None => {
                return ready(Err(AppError::Unauthorized(
                    "Missing API key. Provide via 'Authorization: Bearer <key>' or 'X-API-Key: <key>' header".into(),
                )));
            }
        };

        // Validate the API key against the database
        match services::validate_api_key(pool, &provided_key) {
            Ok((user_id, _key_id)) => ready(Ok(AuthenticatedUser { user_id })),
            Err(e) => ready(Err(e)),
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
    use crate::db::{init_pool, run_migrations};
    use actix_web::{test, web, App, HttpResponse};

    async fn protected_endpoint(user: AuthenticatedUser) -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({
            "user_id": user.user_id
        }))
    }

    fn setup_test_pool() -> DbPool {
        let pool = init_pool("file::memory:?cache=shared").unwrap();
        run_migrations(&pool).unwrap();
        pool
    }

    #[actix_rt::test]
    async fn test_missing_api_key_returns_401() {
        let pool = setup_test_pool();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get().uri("/protected").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_invalid_api_key_returns_401() {
        let pool = setup_test_pool();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("X-API-Key", "usk_invalid_key"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }

    #[actix_rt::test]
    async fn test_valid_api_key_with_bearer() {
        let pool = setup_test_pool();

        // Register a user and get their API key
        let (user, api_key) = services::register_user(&pool, "test@example.com").unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", api_key)))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["user_id"], user.id);
    }

    #[actix_rt::test]
    async fn test_valid_api_key_with_x_api_key_header() {
        let pool = setup_test_pool();

        // Register a user and get their API key
        let (user, api_key) = services::register_user(&pool, "test2@example.com").unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("X-API-Key", api_key))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["user_id"], user.id);
    }

    #[actix_rt::test]
    async fn test_revoked_key_returns_401() {
        let pool = setup_test_pool();

        // Register a user
        let (user, _default_key) = services::register_user(&pool, "test3@example.com").unwrap();

        // Create and then revoke a key
        let (record, api_key) = services::create_api_key(&pool, user.id, "To Revoke").unwrap();
        services::revoke_api_key(&pool, user.id, record.id).unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .route("/protected", web::get().to(protected_endpoint)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("X-API-Key", api_key))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), 401);
    }
}
