//! # URL Shortener
//!
//! A fast, lightweight URL shortener built with Rust, Actix-web, and SQLite.
//!
//! ## Features
//! - Create short URLs from long URLs
//! - Redirect short URLs to original URLs
//! - Track click statistics
//! - RESTful API
//! - Rate limiting for abuse protection
//! - Per-user API key authentication

mod auth;
mod cache;
mod config;
mod db;
mod errors;
mod handlers;
mod models;
mod queries;
mod services;

use actix_governor::{Governor, GovernorConfigBuilder};
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
    let pool =
        db::init_pool(&config.database_url).expect("Failed to create database pool");

    // Run database migrations
    db::run_migrations(&pool).expect("Failed to run database migrations");

    // Initialize cache
    let app_cache = cache::AppCache::new(
        config.url_cache_ttl_secs,
        config.url_cache_max_capacity,
        config.api_key_cache_ttl_secs,
        config.api_key_cache_max_capacity,
    );

    info!(
        "Cache initialized: URL TTL={}s, URL capacity={}, API key TTL={}s, API key capacity={}",
        config.url_cache_ttl_secs,
        config.url_cache_max_capacity,
        config.api_key_cache_ttl_secs,
        config.api_key_cache_max_capacity
    );

    info!(
        "Starting URL Shortener server at http://{}:{}",
        config.host, config.port
    );
    info!("API Documentation:");
    info!("   POST /api/auth/register     - Register with email, get API key");
    info!("   POST /api/auth/keys         - Create new API key");
    info!("   GET  /api/auth/keys         - List your API keys");
    info!("   DELETE /api/auth/keys/{{id}}  - Revoke an API key");
    info!("   POST /api/shorten           - Create a short URL");
    info!("   GET  /api/urls              - List your URLs");
    info!("   GET  /api/urls/{{id}}         - Get URL details");
    info!("   DELETE /api/urls/{{id}}       - Delete a URL");
    info!("   GET  /{{short_code}}          - Redirect to original URL");

    // Capture bind address before moving config into closure
    let bind_addr = format!("{}:{}", config.host, config.port);

    // Configure rate limiting: 60 requests per minute per IP
    // This protects against DoS attacks and API abuse
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(1) // Refill rate: 1 token per second
        .burst_size(60) // Allow bursts up to 60 requests
        .finish()
        .expect("Failed to create rate limiter configuration");

    info!("Rate limiting enabled: 60 requests/minute per IP");
    info!("Per-user API key authentication enabled");

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Add database pool to app state
            .app_data(web::Data::new(pool.clone()))
            // Add base URL to app state
            .app_data(web::Data::new(config.clone()))
            // Add cache to app state
            .app_data(web::Data::new(app_cache.clone()))
            // Enable rate limiting middleware
            .wrap(Governor::new(&governor_conf))
            // Enable logger middleware
            .wrap(Logger::default())
            // Configure routes
            .configure(handlers::configure_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
