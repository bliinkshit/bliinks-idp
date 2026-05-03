// src/db/oauth_queries.rs
use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::AppError;
use super::models::{OAuthAuthorizationCode, OAuthClient, OAuthToken};

pub async fn get_client(
    pool:      &SqlitePool,
    client_id: &str,
) -> Result<Option<OAuthClient>, AppError> {
    sqlx::query_as::<_, OAuthClient>(
        "SELECT id, secret_hash, name, created_at
         FROM oauth_clients WHERE id = ?",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn get_all_clients(pool: &SqlitePool) -> Result<Vec<OAuthClient>, AppError> {
    sqlx::query_as::<_, OAuthClient>(
        "SELECT id, secret_hash, name, created_at
         FROM oauth_clients ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn create_client(
    pool:        &SqlitePool,
    id:          &str,
    secret_hash: &str,
    name:        &str,
) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO oauth_clients (id, secret_hash, name, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(id)
    .bind(secret_hash)
    .bind(name)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_client(pool: &SqlitePool, client_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM oauth_clients WHERE id = ?")
        .bind(client_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn add_redirect_uri(
    pool:      &SqlitePool,
    client_id: &str,
    uri:       &str,
) -> Result<(), AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT OR IGNORE INTO oauth_client_redirects (id, client_id, uri) VALUES (?, ?, ?)",
    )
    .bind(&id)
    .bind(client_id)
    .bind(uri)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn get_client_redirect_uris(
    pool:      &SqlitePool,
    client_id: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT uri FROM oauth_client_redirects WHERE client_id = ?",
    )
    .bind(client_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(rows.into_iter().map(|(uri,)| uri).collect())
}

pub async fn create_authorization_code(
    pool:         &SqlitePool,
    code:         &str,
    client_id:    &str,
    user_id:      &str,
    redirect_uri: &str,
    scopes:       &str,
) -> Result<(), AppError> {
    let expires = (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    sqlx::query(
        "INSERT INTO oauth_authorization_codes
             (code, client_id, user_id, redirect_uri, scopes, expires_at, used_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(code)
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(scopes)
    .bind(&expires)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn consume_authorization_code(
    pool: &SqlitePool,
    code: &str,
) -> Result<Option<OAuthAuthorizationCode>, AppError> {
    let row = sqlx::query_as::<_, OAuthAuthorizationCode>(
        "SELECT code, client_id, user_id, redirect_uri, scopes, expires_at, used_at
         FROM oauth_authorization_codes
         WHERE code = ? AND used_at IS NULL AND expires_at > ?",
    )
    .bind(code)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if row.is_some() {
        sqlx::query(
            "UPDATE oauth_authorization_codes SET used_at = ? WHERE code = ?",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(code)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(row)
}

pub async fn create_token(
    pool:       &SqlitePool,
    token_hash: &str,
    client_id:  &str,
    user_id:    &str,
    kind:       &str,
    scopes:     &str,
    expires_at: &str,
) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO oauth_tokens
             (token_hash, client_id, user_id, kind, scopes, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(user_id)
    .bind(kind)
    .bind(scopes)
    .bind(expires_at)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn get_token(
    pool:       &SqlitePool,
    token_hash: &str,
    kind:       &str,
) -> Result<Option<OAuthToken>, AppError> {
    sqlx::query_as::<_, OAuthToken>(
        "SELECT token_hash, client_id, user_id, kind, scopes, expires_at, created_at
         FROM oauth_tokens
         WHERE token_hash = ? AND kind = ? AND expires_at > ?",
    )
    .bind(token_hash)
    .bind(kind)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn revoke_token(
    pool:       &SqlitePool,
    token_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM oauth_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn revoke_tokens_for_user_and_client(
    pool:      &SqlitePool,
    user_id:   &str,
    client_id: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM oauth_tokens WHERE user_id = ? AND client_id = ?",
    )
    .bind(user_id)
    .bind(client_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_expired_oauth(pool: &SqlitePool) {
    let now = Utc::now().to_rfc3339();

    let _ = sqlx::query(
        "DELETE FROM oauth_authorization_codes
         WHERE expires_at < ? OR used_at IS NOT NULL",
    )
    .bind(&now)
    .execute(pool)
    .await;

    let _ = sqlx::query("DELETE FROM oauth_tokens WHERE expires_at < ?")
        .bind(&now)
        .execute(pool)
        .await;
}
