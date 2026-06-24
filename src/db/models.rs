// src/db/models.rs
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id:                Uuid,
    pub username:          String,
    pub password:          String,
    pub role:              Uuid,
    pub display_name:      Option<String>,
    pub color:             Option<String>,
    pub avatar_updated_at: Option<DateTime<Utc>>,
    pub date_created:      DateTime<Utc>,
    pub deleted_at:        Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PasswordReset {
    pub token_hash: String,
    pub user_id:    Uuid,
    pub expires_at: DateTime<Utc>,
    pub used_at:    Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthClient {
    pub id:          Uuid,
    pub secret_hash: String,
    pub name:        String,
    pub created_at:  DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct OAuthAuthorizationCode {
    pub code:         String,
    pub client_id:    Uuid,
    pub user_id:      Uuid,
    pub redirect_uri: String,
    pub scopes:       String,
    pub expires_at:   DateTime<Utc>,
    pub used_at:      Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct OAuthToken {
    pub token_hash: String,
    pub client_id:  Uuid,
    pub user_id:    Uuid,
    pub kind:       String,
    pub scopes:     String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }
}
