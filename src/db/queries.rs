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
    role_id:  &str,
    created:  &str,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "INSERT OR IGNORE INTO users (id, username, password, role, color, date_created)
         VALUES (?, ?, ?, ?, NULL, ?)",
    )
    .bind(id)
    .bind(username)
    .bind(password)
    .bind(role_id)
    .bind(created)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_user_by_username(
    pool:     &SqlitePool,
    username: &str,
) -> Result<Option<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, role, display_name, color, avatar_updated_at, date_created, deleted_at
         FROM users WHERE username = ? COLLATE NOCASE",
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
        "SELECT id, username, password, role, display_name, color, avatar_updated_at, date_created, deleted_at
         FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn update_user_password(
    pool:          &SqlitePool,
    user_id:       &str,
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
        "SELECT id, username, password, role, display_name, color, avatar_updated_at, date_created, deleted_at
         FROM users ORDER BY date_created ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn set_user_role(
    pool:    &SqlitePool,
    user_id: &str,
    role_id: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET role = ? WHERE id = ?")
        .bind(role_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn update_user_display_name(
    pool:         &SqlitePool,
    user_id:      &str,
    display_name: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET display_name = ? WHERE id = ?")
        .bind(display_name)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn update_user_color(
    pool:    &SqlitePool,
    user_id: &str,
    color:   Option<&str>,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET color = ? WHERE id = ?")
        .bind(color)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn set_avatar_updated_at(
    pool:    &SqlitePool,
    user_id: &str,
    ts:      &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET avatar_updated_at = ? WHERE id = ?")
        .bind(ts)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_user(
    pool:       &SqlitePool,
    user_id:    &str,
    deleted_role_id: &str,
) -> Result<(), AppError> {
    let deleted_username = format!("deleted_{}", &user_id[..12]);
    let now              = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE users
         SET deleted_at        = ?,
             role              = ?,
             username          = ?,
             password          = '',
             display_name      = NULL,
             color             = NULL,
             avatar_updated_at = NULL
         WHERE id = ?",
    )
    .bind(&now)
    .bind(deleted_role_id)
    .bind(&deleted_username)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}
