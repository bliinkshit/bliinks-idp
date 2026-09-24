use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::HeaderMap;
use base64::Engine;
use sqlx::PgPool;

use crate::{
    db::{
        models::OAuthClient,
        oauth_queries::get_client,
    },
    error::AppError,
};

pub fn extract_basic_credentials(
    headers: &HeaderMap,
) -> Option<(String, String)> {
    let authorization = headers
        .get("authorization")?
        .to_str()
        .ok()?;

    let encoded = authorization.strip_prefix("Basic ")?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;

    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;

    Some((
        client_id.to_string(),
        client_secret.to_string(),
    ))
}

pub async fn authenticate_client(
    pool: &PgPool,
    client_id: &str,
    client_secret: &str,
) -> Result<Option<OAuthClient>, AppError> {
    let Ok(client_id) = client_id.parse() else {
        return Ok(None);
    };

    let Some(client) = get_client(pool, client_id).await? else {
        return Ok(None);
    };

    let Ok(password_hash) = PasswordHash::new(&client.secret_hash) else {
        return Ok(None);
    };

    if Argon2::default()
        .verify_password(client_secret.as_bytes(), &password_hash)
        .is_err()
    {
        return Ok(None);
    }

    Ok(Some(client))
}