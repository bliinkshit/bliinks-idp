// src/db/mod.rs
pub mod models;
pub mod queries;
pub mod oauth_queries;

use sqlx::{sqlite::SqlitePoolOptions, Executor, SqlitePool};
use sqlx::migrate::Migrate;
use tracing::info;

use crate::error::AppError;

pub async fn init_pool(url: &str) -> Result<SqlitePool, AppError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .idle_timeout(std::time::Duration::from_secs(600))
        .connect(url)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let migrator = sqlx::migrate!("./migrations");

    {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        for pragma in &[
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA busy_timeout=5000",
            "PRAGMA foreign_keys=ON",
        ] {
            conn.execute(*pragma).await
                .map_err(|e| AppError::Internal(e.to_string()))?;
        }

        let applied = Migrate::list_applied_migrations(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

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
