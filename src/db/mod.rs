// src/db/mod.rs
pub mod models;
pub mod queries;
pub mod oauth_queries;

use sqlx::{sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous, SqlitePoolOptions}, SqlitePool};
use sqlx::migrate::Migrate;
use tracing::info;
use std::str::FromStr;

use crate::error::AppError;

pub async fn init_pool(url: &str) -> Result<SqlitePool, AppError> {
    let opts = SqliteConnectOptions::from_str(url)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5))
        .foreign_keys(true)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .idle_timeout(std::time::Duration::from_secs(600))
        .connect_with(opts)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let migrator = sqlx::migrate!("./migrations");

    {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let applied = Migrate::list_applied_migrations(&mut *conn)
            .await
            .unwrap_or_default();

        for migration in migrator.iter() {
            if applied.iter().any(|m| m.version == migration.version) {
                info!("skipping migration {} ({})", migration.version, migration.description);
            } else {
                info!("running migration {} ({})", migration.version, migration.description);
            }
        }
    }

    migrator
        .run(&pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(pool)
}
