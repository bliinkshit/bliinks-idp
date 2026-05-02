// src/db/mod.rs
pub mod models;
pub mod queries;

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

use crate::error::AppError;

pub async fn init_pool(url: &str) -> Result<SqlitePool, AppError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(pool)
}
