// src/db/mod.rs
pub mod models;
pub mod queries;
pub mod oauth_queries;

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tracing::{info};
use tracing_subscriber::{fmt, EnvFilter};
use sqlx::migrate::Migrate;

//internal
use crate::error::AppError;

pub async fn init_pool(url: &str) -> Result<SqlitePool, AppError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let migrator = sqlx::migrate!("./migrations");

    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let applied_migrations =
        Migrate::list_applied_migrations(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

    for migration in migrator.iter() {
        let already_applied = applied_migrations
            .iter()
            .any(|m| m.version == migration.version);

        if already_applied {
            info!("skipping migration {} ({})", migration.version, migration.description);
        } else {
            info!("running migration {} ({})", migration.version, migration.description);
        }
    }

    migrator
        .run(&pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(pool)
}
