// src/db/queries.rs
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;
use super::models::{Invite, PasswordReset, User};

pub async fn create_user(
    pool:     &PgPool,
    id:       Uuid,
    username: &str,
    password: &str,
    role_id:  Uuid,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "INSERT INTO users (id, username, password, role, color, date_created)
         VALUES ($1, $2, $3, $4, NULL, NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(username)
    .bind(password)
    .bind(role_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_user_by_username(
    pool:     &PgPool,
    username: &str,
) -> Result<Option<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, role, display_name, color, avatar_updated_at, date_created, deleted_at
         FROM users WHERE username ILIKE $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn get_user_by_id(
    pool: &PgPool,
    id:   Uuid,
) -> Result<Option<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, role, display_name, color, avatar_updated_at, date_created, deleted_at
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn update_user_password(
    pool:          &PgPool,
    user_id:       Uuid,
    password_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET password = $1 WHERE id = $2")
        .bind(password_hash)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_sessions_for_user(
    pool:    &PgPool,
    user_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn issue_password_reset(
    pool:     &PgPool,
    user_id:  Uuid,
    base_url: &str,
) -> Result<String, AppError> {
    use rand::RngCore;
    use argon2::password_hash::rand_core::OsRng;
    use sha2::{Digest, Sha256};

    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token      = hex::encode(raw);
    let token_hash = hex::encode(Sha256::digest(token.trim().as_bytes()));
    let expires    = Utc::now() + chrono::Duration::hours(1);

    sqlx::query(
        "INSERT INTO password_resets (token_hash, user_id, expires_at, used_at)
         VALUES ($1, $2, $3, NULL)
         ON CONFLICT (token_hash) DO UPDATE SET
            user_id    = EXCLUDED.user_id,
            expires_at = EXCLUDED.expires_at,
            used_at    = NULL",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(expires)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(format!("{}/auth/reset?token={}", base_url.trim_end_matches('/'), token))
}

pub async fn get_password_reset(
    pool:       &PgPool,
    token_hash: &str,
) -> Result<Option<PasswordReset>, AppError> {
    sqlx::query_as::<_, PasswordReset>(
        "SELECT token_hash, user_id, expires_at, used_at
         FROM password_resets
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn mark_password_reset_used(
    pool:       &PgPool,
    token_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("UPDATE password_resets SET used_at = NOW() WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_expired_password_resets(pool: &PgPool) {
    let _ = sqlx::query(
        "DELETE FROM password_resets WHERE expires_at < NOW() OR used_at IS NOT NULL",
    )
    .execute(pool)
    .await;
}

pub async fn get_all_users(pool: &PgPool) -> Result<Vec<User>, AppError> {
    sqlx::query_as::<_, User>(
        "SELECT id, username, password, role, display_name, color, avatar_updated_at, date_created, deleted_at
         FROM users ORDER BY date_created ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn set_user_role(
    pool:    &PgPool,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(role_id)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn update_user_display_name(
    pool:         &PgPool,
    user_id:      Uuid,
    display_name: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(display_name)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn update_user_color(
    pool:    &PgPool,
    user_id: Uuid,
    color:   Option<&str>,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET color = $1 WHERE id = $2")
        .bind(color)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn set_avatar_updated_at(
    pool:    &PgPool,
    user_id: Uuid,
    ts:      DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET avatar_updated_at = $1 WHERE id = $2")
        .bind(ts)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_user(
    pool:            &PgPool,
    user_id:         Uuid,
    deleted_role_id: Uuid,
) -> Result<(), AppError> {
    let deleted_username = format!("deleted_{}", &user_id.to_string()[..12]);

    sqlx::query(
        "UPDATE users
         SET deleted_at        = NOW(),
             role              = $1,
             username          = $2,
             password          = '',
             display_name      = NULL,
             color             = NULL,
             avatar_updated_at = NULL
         WHERE id = $3",
    )
    .bind(deleted_role_id)
    .bind(&deleted_username)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn create_invite(
    pool:      &PgPool,
    id:        Uuid,
    code:      &str,
    issuer_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO invites (id, code, issuer_id) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(code)
    .bind(issuer_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn get_invite_by_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<Invite>, AppError> {
    sqlx::query_as::<_, Invite>(
        "SELECT id, code, issuer_id, recipient_id, created_at
         FROM invites WHERE code = $1 AND recipient_id IS NULL",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn redeem_invite(
    pool:         &PgPool,
    code:         &str,
    recipient_id: Uuid,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE invites SET recipient_id = $1
         WHERE code = $2 AND recipient_id IS NULL",
    )
    .bind(recipient_id)
    .bind(code)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_invites_by_issuer(
    pool:      &PgPool,
    issuer_id: Uuid,
) -> Result<Vec<Invite>, AppError> {
    sqlx::query_as::<_, Invite>(
        "SELECT id, code, issuer_id, recipient_id, created_at
         FROM invites WHERE issuer_id = $1 ORDER BY created_at DESC",
    )
    .bind(issuer_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}
