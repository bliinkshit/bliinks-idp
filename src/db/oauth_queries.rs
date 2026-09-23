// src/db/oauth_queries.rs
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

// internal
use crate::error::AppError;
use super::models::{OAuthAuthorizationCode, OAuthClient, OAuthToken};

pub async fn get_client(
    pool:      &PgPool,
    client_id: Uuid,
) -> Result<Option<OAuthClient>, AppError> {
    sqlx::query_as::<_, OAuthClient>(
        "SELECT id, secret_hash, name, created_at
         FROM oauth_clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn get_all_clients(pool: &PgPool) -> Result<Vec<OAuthClient>, AppError> {
    sqlx::query_as::<_, OAuthClient>(
        "SELECT id, secret_hash, name, created_at
         FROM oauth_clients ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn create_client(
    pool:        &PgPool,
    id:          Uuid,
    secret_hash: &str,
    name:        &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO oauth_clients (id, secret_hash, name, created_at) VALUES ($1, $2, $3, NOW())",
    )
    .bind(id)
    .bind(secret_hash)
    .bind(name)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_client(pool: &PgPool, client_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(client_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn add_redirect_uri(
    pool:      &PgPool,
    client_id: Uuid,
    uri:       &str,
) -> Result<(), AppError> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO oauth_client_redirects (id, client_id, uri) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(client_id)
    .bind(uri)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn get_client_redirect_uris(
    pool:      &PgPool,
    client_id: Uuid,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT uri FROM oauth_client_redirects WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(rows.into_iter().map(|(uri,)| uri).collect())
}

pub async fn create_authorization_code(
    pool:         &PgPool,
    code:         &str,
    client_id:    Uuid,
    user_id:      Uuid,
    redirect_uri: &str,
    scopes:       &str,
) -> Result<(), AppError> {
    let expires = Utc::now() + chrono::Duration::minutes(crate::oauth::token::AUTH_CODE_TTL_MINUTES);

    sqlx::query(
        "INSERT INTO oauth_authorization_codes
             (code, client_id, user_id, redirect_uri, scopes, expires_at, used_at)
         VALUES ($1, $2, $3, $4, $5, $6, NULL)",
    )
    .bind(code)
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(scopes)
    .bind(expires)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn consume_authorization_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<OAuthAuthorizationCode>, AppError> {
    let row = sqlx::query_as::<_, OAuthAuthorizationCode>(
        "SELECT code, client_id, user_id, redirect_uri, scopes, expires_at, used_at
         FROM oauth_authorization_codes
         WHERE code = $1 AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if row.is_some() {
        sqlx::query(
            "UPDATE oauth_authorization_codes SET used_at = NOW() WHERE code = $1",
        )
        .bind(code)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(row)
}

pub async fn create_token(
    pool:       &PgPool,
    token_hash: &str,
    client_id:  Uuid,
    user_id:    Uuid,
    kind:       &str,
    scopes:     &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO oauth_tokens
             (token_hash, client_id, user_id, kind, scopes, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())",
    )
    .bind(token_hash)
    .bind(client_id)
    .bind(user_id)
    .bind(kind)
    .bind(scopes)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn get_token(
    pool:       &PgPool,
    token_hash: &str,
    kind:       &str,
) -> Result<Option<OAuthToken>, AppError> {
    sqlx::query_as::<_, OAuthToken>(
        "SELECT token_hash, client_id, user_id, kind, scopes, expires_at, created_at
         FROM oauth_tokens
         WHERE token_hash = $1 AND kind = $2 AND expires_at > NOW()",
    )
    .bind(token_hash)
    .bind(kind)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn revoke_token(
    pool:       &PgPool,
    token_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM oauth_tokens WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn revoke_tokens_for_user_and_client(
    pool:      &PgPool,
    user_id:   Uuid,
    client_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM oauth_tokens WHERE user_id = $1 AND client_id = $2",
    )
    .bind(user_id)
    .bind(client_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn revoke_all_tokens_for_user(
    pool:    &PgPool,
    user_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM oauth_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(())
}

pub async fn delete_expired_oauth(pool: &PgPool) {
    let _ = sqlx::query(
        "DELETE FROM oauth_authorization_codes
         WHERE expires_at < NOW() OR used_at IS NOT NULL",
    )
    .execute(pool)
    .await;

    let _ = sqlx::query("DELETE FROM oauth_tokens WHERE expires_at < NOW()")
        .execute(pool)
        .await;
}

pub async fn get_connected_clients_for_user(
    pool:    &PgPool,
    user_id: Uuid,
) -> Result<Vec<OAuthClient>, AppError> {
    sqlx::query_as::<_, OAuthClient>(
        "SELECT DISTINCT c.id, c.secret_hash, c.name, c.created_at
         FROM oauth_clients c
         INNER JOIN oauth_tokens t ON t.client_id = c.id
         WHERE t.user_id = $1 AND t.expires_at > NOW()
         ORDER BY c.name ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}
