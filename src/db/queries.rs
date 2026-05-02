// src/db/queries.rs
use sqlx::SqlitePool;

use crate::error::AppError;
use super::models::User;

pub async fn create_user(
    pool:     &SqlitePool,
    id:       &str,
    username: &str,
    password: &str,
    created:  &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO users (id, username, password, approved, admin, color, date_created)
         VALUES (?, ?, ?, 0, 0, NULL, ?)",
    )
    .bind(id)
    .bind(username)
    .bind(password)
    .bind(created)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn get_user_by_username(
    pool:     &SqlitePool,
    username: &str,
) -> Result<Option<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, approved, admin, color, date_created
         FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}
