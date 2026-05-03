// src/db/models.rs
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id:           String,
    pub username:     String,
    pub password:     String,
    pub approved:     bool,
    pub admin:        bool,
    pub color:        Option<String>,
    pub date_created: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct PasswordReset {
    pub token_hash: String,
    pub user_id:    String,
    pub expires_at: String,
    pub used_at:    Option<String>,
}
