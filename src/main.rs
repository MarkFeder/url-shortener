//! # URL Shortener
//!
//! A fast, lightweight URL shortener built with Rust, Actix-web, and SQLite.
//!
//! ## Features
//! - Create short URLs from long URLs
//! - Redirect short URLs to original URLs
//! - Track click statistics
//! - RESTful API

mod config;
mod db;
mod errors;
mod handlers;
mod models;
mod services;

use actix_web::{middleware::Logger, web, App, HttpServer};
use log::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize environment variables from .env file
    dotenv::dotenv().ok();

    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load configuration
    let config = config::Config::from_env();

    // Initialize database connection pool
    let pool = db::init_pool(&config.database_url)
        .expect("Failed to create database pool");

    // Run database migrations
    db::run_migrations(&pool).expect("Failed to run database migrations");

    info!(
        "🚀 Starting URL Shortener server at http://{}:{}",
        config.host, config.port
    );
    info!("📝 API Documentation:");
    info!("   POST /api/shorten     - Create a short URL");
    info!("   GET  /api/urls        - List all URLs");
    info!("   GET  /api/urls/{{id}}   - Get URL details");
    info!("   DELETE /api/urls/{{id}} - Delete a URL");
    info!("   GET  /{{short_code}}    - Redirect to original URL");

    // Capture bind address before moving config into closure
    let bind_addr = format!("{}:{}", config.host, config.port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Add database pool to app state
            .app_data(web::Data::new(pool.clone()))
            // Add base URL to app state
            .app_data(web::Data::new(config.clone()))
            // Enable logger middleware
            .wrap(Logger::default())
            // Configure routes
            .configure(handlers::configure_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
