//! Application configuration module.
//!
//! Handles loading configuration from environment variables.

use std::env;

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Database file path
    pub database_url: String,
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// Base URL for generating short links
    pub base_url: String,
    /// Length of generated short codes
    pub short_code_length: usize,
}

impl Config {
    /// Load configuration from environment variables
    ///
    /// # Environment Variables
    /// - `DATABASE_URL`: Path to SQLite database (default: "urls.db")
    /// - `HOST`: Server host (default: "127.0.0.1")
    /// - `PORT`: Server port (default: 8080)
    /// - `BASE_URL`: Base URL for short links (default: "http://localhost:8080")
    /// - `SHORT_CODE_LENGTH`: Length of generated codes (default: 7)
    pub fn from_env() -> Self {
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .expect("PORT must be a valid number");

        let base_url = env::var("BASE_URL")
            .unwrap_or_else(|_| format!("http://{}:{}", host, port));

        Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "urls.db".to_string()),
            host,
            port,
            base_url,
            short_code_length: env::var("SHORT_CODE_LENGTH")
                .unwrap_or_else(|_| "7".to_string())
                .parse()
                .expect("SHORT_CODE_LENGTH must be a valid number"),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: "urls.db".to_string(),
            host: "127.0.0.1".to_string(),
            port: 8080,
            base_url: "http://localhost:8080".to_string(),
            short_code_length: 7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.database_url, "urls.db");
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert_eq!(config.short_code_length, 7);
    }
}
