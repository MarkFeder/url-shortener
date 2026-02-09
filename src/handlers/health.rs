//! Health check endpoint handler.

use actix_web::{get, HttpResponse};

/// Health check endpoint
#[get("/health")]
pub(super) async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}
