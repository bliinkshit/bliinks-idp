// src/db/queries.rs
use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::AppError;
use super::models::{PasswordReset, User};

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

pub async fn get_user_by_id(
    pool: &SqlitePool,
    id:   &str,
) -> Result<Option<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, approved, admin, color, date_created
         FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn update_user_password(
    pool:        &SqlitePool,
    user_id:     &str,
    password_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET password = ? WHERE id = ?")
        .bind(password_hash)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_sessions_for_user(
    pool:    &SqlitePool,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn create_password_reset(
    pool:       &SqlitePool,
    token_hash: &str,
    user_id:    &str,
) -> Result<(), AppError> {
    let expires = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    sqlx::query(
        "INSERT INTO password_resets (token_hash, user_id, expires_at, used_at)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT(token_hash) DO UPDATE SET
            user_id    = excluded.user_id,
            expires_at = excluded.expires_at,
            used_at    = NULL",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(&expires)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn get_password_reset(
    pool:       &SqlitePool,
    token_hash: &str,
) -> Result<Option<PasswordReset>, AppError> {
    sqlx::query_as::<_, PasswordReset>(
        "SELECT token_hash, user_id, expires_at, used_at
         FROM password_resets
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
    )
    .bind(token_hash)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn mark_password_reset_used(
    pool:       &SqlitePool,
    token_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE password_resets SET used_at = ? WHERE token_hash = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(token_hash)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_expired_password_resets(pool: &SqlitePool) {
    let _ = sqlx::query(
        "DELETE FROM password_resets WHERE expires_at < ? OR used_at IS NOT NULL",
    )
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await;
}
pub async fn get_all_users(pool: &SqlitePool) -> Result<Vec<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, approved, admin, color, date_created
         FROM users ORDER BY date_created ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn set_user_approved(
    pool:    &SqlitePool,
    user_id: &str,
    approved: bool,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET approved = ? WHERE id = ?")
        .bind(approved)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn issue_password_reset(
    pool:     &SqlitePool,
    user_id:  &str,
    base_url: &str,
) -> Result<String, AppError> {
    use rand::RngCore;
    use argon2::password_hash::rand_core::OsRng;
    use sha2::{Digest, Sha256};

    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token      = hex::encode(raw);
    let token_hash = hex::encode(Sha256::digest(token.trim().as_bytes()));
    let expires    = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    sqlx::query(
        "INSERT INTO password_resets (token_hash, user_id, expires_at, used_at)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT(token_hash) DO UPDATE SET
            user_id    = excluded.user_id,
            expires_at = excluded.expires_at,
            used_at    = NULL",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(&expires)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(format!("{}/auth/reset?token={}", base_url.trim_end_matches('/'), token))
}

pub async fn set_user_admin(
    pool:    &SqlitePool,
    user_id: &str,
    admin:   bool,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET admin = ? WHERE id = ?")
        .bind(admin)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}
