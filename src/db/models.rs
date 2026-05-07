// src/db/models.rs
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id:                String,
    pub username:          String,
    pub password:          String,
    pub approved:          bool,
    pub admin:             bool,
    pub display_name:      Option<String>,
    pub color:             Option<String>,
    pub avatar_updated_at: Option<String>,
    pub date_created:      String,
    pub deleted_at:        Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PasswordReset {
    pub token_hash: String,
    pub user_id:    String,
    pub expires_at: String,
    pub used_at:    Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthClient {
    pub id:          String,
    pub secret_hash: String,
    pub name:        String,
    pub created_at:  String,
}

#[derive(Debug, Clone, FromRow)]
pub struct OAuthAuthorizationCode {
    pub code:         String,
    pub client_id:    String,
    pub user_id:      String,
    pub redirect_uri: String,
    pub scopes:       String,
    pub expires_at:   String,
    pub used_at:      Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct OAuthToken {
    pub token_hash: String,
    pub client_id:  String,
    pub user_id:    String,
    pub kind:       String,
    pub scopes:     String,
    pub expires_at: String,
    pub created_at: String,
}

impl User {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }
}
