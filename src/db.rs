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

/// Initialize the database connection pool with WAL mode enabled
///
/// WAL (Write-Ahead Logging) mode provides better concurrent read performance
/// and improved reliability compared to the default rollback journal mode.
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

    // Enable WAL mode for better concurrent read performance
    // Skip for in-memory databases (used in tests)
    if !database_url.contains(":memory:") {
        configure_wal_mode(&pool)?;
    }

    Ok(pool)
}

/// Configure SQLite WAL mode and related pragmas for optimal performance
fn configure_wal_mode(pool: &DbPool) -> Result<(), AppError> {
    let conn = pool
        .get()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get connection: {}", e)))?;

    // Enable WAL mode for concurrent reads during writes
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA cache_size = -64000;
         PRAGMA foreign_keys = ON;",
    )
    .map_err(|e| AppError::DatabaseError(format!("Failed to configure WAL mode: {}", e)))?;

    log::info!("SQLite WAL mode enabled for better concurrency");
    Ok(())
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

    // Create users table first (foreign key dependency)
    conn.execute(Schema::CREATE_USERS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create users table: {}", e)))?;

    // Create api_keys table
    conn.execute(Schema::CREATE_API_KEYS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create api_keys table: {}", e)))?;

    // Create urls table (now with user_id foreign key)
    conn.execute(Schema::CREATE_URLS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create urls table: {}", e)))?;

    conn.execute(Schema::CREATE_SHORT_CODE_INDEX, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create index: {}", e)))?;

    conn.execute(Schema::CREATE_CLICK_LOGS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create click_logs table: {}", e)))?;

    // Create tags table
    conn.execute(Schema::CREATE_TAGS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create tags table: {}", e)))?;

    // Create url_tags junction table
    conn.execute(Schema::CREATE_URL_TAGS_TABLE, [])
        .map_err(|e| AppError::DatabaseError(format!("Failed to create url_tags table: {}", e)))?;

    // Migration: Add user_id column to existing urls table if it doesn't exist
    // This handles upgrading from the old schema
    let has_user_id: i32 = conn
        .query_row(Schema::COLUMN_EXISTS, ["urls", "user_id"], |row| row.get(0))
        .unwrap_or(0);

    if has_user_id == 0 {
        // Only run if the table exists but lacks user_id column
        let table_exists: i32 = conn
            .query_row(Schema::TABLE_EXISTS, ["urls"], |row| row.get(0))
            .unwrap_or(0);

        if table_exists > 0 {
            // Add the user_id column to existing table
            match conn.execute(Schema::ADD_USER_ID_TO_URLS, []) {
                Ok(_) => log::info!("Added user_id column to existing urls table"),
                Err(e) => {
                    // Ignore if column already exists (race condition or retry)
                    if !e.to_string().contains("duplicate column") {
                        return Err(AppError::DatabaseError(format!(
                            "Failed to add user_id column: {}",
                            e
                        )));
                    }
                }
            }
        }
    }

    // Migration: Add new click tracking columns to click_logs
    let click_log_columns = [
        ("browser", Schema::ADD_BROWSER_TO_CLICK_LOGS),
        ("browser_version", Schema::ADD_BROWSER_VERSION_TO_CLICK_LOGS),
        ("os", Schema::ADD_OS_TO_CLICK_LOGS),
        ("device_type", Schema::ADD_DEVICE_TYPE_TO_CLICK_LOGS),
        ("referer_domain", Schema::ADD_REFERER_DOMAIN_TO_CLICK_LOGS),
    ];

    for (column_name, alter_sql) in &click_log_columns {
        let has_column: i32 = conn
            .query_row(Schema::COLUMN_EXISTS, ["click_logs", column_name], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        if has_column == 0 {
            match conn.execute(alter_sql, []) {
                Ok(_) => log::info!("Added {} column to click_logs table", column_name),
                Err(e) => {
                    if !e.to_string().contains("duplicate column") {
                        return Err(AppError::DatabaseError(format!(
                            "Failed to add {} column: {}",
                            column_name, e
                        )));
                    }
                }
            }
        }
    }

    // Create indexes on click_logs for analytics performance
    conn.execute(Schema::CREATE_CLICK_LOGS_URL_ID_INDEX, [])
        .map_err(|e| {
            AppError::DatabaseError(format!("Failed to create click_logs url_id index: {}", e))
        })?;

    conn.execute(Schema::CREATE_CLICK_LOGS_URL_ID_CLICKED_AT_INDEX, [])
        .map_err(|e| {
            AppError::DatabaseError(format!(
                "Failed to create click_logs url_id_clicked_at index: {}",
                e
            ))
        })?;

    log::info!("Database migrations completed successfully");
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

        // Verify urls table exists
        let count: i32 = conn
            .query_row(Schema::TABLE_EXISTS, ["urls"], |row| row.get(0))
            .expect("Should query");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_users_table_created() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        run_migrations(&pool).expect("Should run migrations");

        let conn = pool.get().expect("Should get connection");

        // Verify users table exists
        let count: i32 = conn
            .query_row(Schema::TABLE_EXISTS, ["users"], |row| row.get(0))
            .expect("Should query");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_api_keys_table_created() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        run_migrations(&pool).expect("Should run migrations");

        let conn = pool.get().expect("Should get connection");

        // Verify api_keys table exists
        let count: i32 = conn
            .query_row(Schema::TABLE_EXISTS, ["api_keys"], |row| row.get(0))
            .expect("Should query");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_click_logs_table_created() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        run_migrations(&pool).expect("Should run migrations");

        let conn = pool.get().expect("Should get connection");

        // Verify click_logs table exists
        let count: i32 = conn
            .query_row(Schema::TABLE_EXISTS, ["click_logs"], |row| row.get(0))
            .expect("Should query");

        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_conn() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        let conn = get_conn(&pool);
        assert!(conn.is_ok());
    }

    #[test]
    fn test_pool_max_connections() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");

        // Verify we can get multiple connections up to the pool size
        let mut connections = Vec::new();
        for _ in 0..5 {
            let conn = pool.get();
            assert!(conn.is_ok());
            connections.push(conn.unwrap());
        }
    }

    #[test]
    fn test_click_logs_new_columns_exist() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        run_migrations(&pool).expect("Should run migrations");

        let conn = pool.get().expect("Should get connection");

        for column in &["browser", "browser_version", "os", "device_type", "referer_domain"] {
            let has_column: i32 = conn
                .query_row(Schema::COLUMN_EXISTS, ["click_logs", column], |row| row.get(0))
                .expect("Should query column existence");
            assert_eq!(has_column, 1, "Column {} should exist in click_logs", column);
        }
    }

    #[test]
    fn test_click_logs_indexes_created() {
        let pool = init_pool("file::memory:?cache=shared").expect("Should create in-memory pool");
        run_migrations(&pool).expect("Should run migrations");

        let conn = pool.get().expect("Should get connection");

        let idx_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_click_logs_url_id'",
                [],
                |row| row.get(0),
            )
            .expect("Should query index");
        assert_eq!(idx_count, 1, "idx_click_logs_url_id should exist");

        let idx_count2: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_click_logs_url_id_clicked_at'",
                [],
                |row| row.get(0),
            )
            .expect("Should query index");
        assert_eq!(idx_count2, 1, "idx_click_logs_url_id_clicked_at should exist");
    }
}
