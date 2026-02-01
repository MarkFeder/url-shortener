//! Database module for SQLite connection and migrations.
//!
//! Uses r2d2 connection pool for efficient connection management.

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

use crate::errors::AppError;

/// Type alias for the SQLite connection pool
pub type DbPool = Pool<SqliteConnectionManager>;

/// Type alias for a pooled database connection
pub type DbConnection = PooledConnection<SqliteConnectionManager>;

/// Initialize the database connection pool
///
/// # Arguments
/// * `database_url` - Path to the SQLite database file
///
/// # Returns
/// * `Result<DbPool, AppError>` - The connection pool or an error
pub fn init_pool(database_url: &str) -> Result<DbPool, AppError> {
    let manager = SqliteConnectionManager::file(database_url);
    let pool = Pool::builder()
        .max_size(10)
        .build(manager)
        .map_err(|e| AppError::DatabaseError(format!("Failed to create pool: {}", e)))?;

    Ok(pool)
}

/// Run database migrations to create necessary tables
///
/// # Arguments
/// * `pool` - Reference to the database connection pool
///
/// # Returns
/// * `Result<(), AppError>` - Success or an error
pub fn run_migrations(pool: &DbPool) -> Result<(), AppError> {
    let conn = pool
        .get()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

    // Create the urls table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS urls (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            short_code      TEXT NOT NULL UNIQUE,
            original_url    TEXT NOT NULL,
            clicks          INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at      TEXT
        )",
        [],
    )
    .map_err(|e| AppError::DatabaseError(format!("Failed to create urls table: {}", e)))?;

    // Create index on short_code for fast lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_short_code ON urls (short_code)",
        [],
    )
    .map_err(|e| AppError::DatabaseError(format!("Failed to create index: {}", e)))?;

    // Create the clicks table for detailed analytics (optional feature)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS click_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id          INTEGER NOT NULL,
            clicked_at      TEXT NOT NULL DEFAULT (datetime('now')),
            ip_address      TEXT,
            user_agent      TEXT,
            referer         TEXT,
            FOREIGN KEY (url_id) REFERENCES urls (id) ON DELETE CASCADE
        )",
        [],
    )
    .map_err(|e| AppError::DatabaseError(format!("Failed to create click_logs table: {}", e)))?;

    log::info!("✅ Database migrations completed successfully");
    Ok(())
}

/// Get a connection from the pool
pub fn get_conn(pool: &DbPool) -> Result<DbConnection, AppError> {
    pool.get()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_pool_and_migrations() {
        // Use shared cache mode so all connections share the same in-memory database
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        run_migrations(&pool).expect("Should run migrations");

        let conn = pool.get().expect("Should get connection");

        // Verify table exists
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='urls'",
                [],
                |row| row.get(0),
            )
            .expect("Should query");

        assert_eq!(count, 1);
    }
}
