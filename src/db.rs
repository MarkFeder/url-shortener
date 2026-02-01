//! Database module for SQLite connection and migrations.
//!
//! Uses r2d2 connection pool for efficient connection management.

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

use crate::errors::AppError;
use crate::queries::Schema;

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

    conn.execute(Schema::CREATE_URLS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create urls table: {}", e)))?;

    conn.execute(Schema::CREATE_SHORT_CODE_INDEX, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create index: {}", e)))?;

    conn.execute(Schema::CREATE_CLICK_LOGS_TABLE, [])
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
