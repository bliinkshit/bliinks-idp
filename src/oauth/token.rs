// src/oauth/token.rs
use argon2::password_hash::rand_core::OsRng;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const ACCESS_TOKEN_TTL_MINUTES: i64 = 15;
pub const REFRESH_TOKEN_TTL_DAYS:   i64 = 30;
pub const AUTH_CODE_TTL_MINUTES:    i64 = 10;

pub fn generate() -> (String, String) {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let hash  = hex::encode(Sha256::digest(token.as_bytes()));
    (token, hash)
}

pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn access_token_expiry() -> DateTime<Utc> {
    Utc::now() + chrono::Duration::minutes(ACCESS_TOKEN_TTL_MINUTES)
}

pub fn refresh_token_expiry() -> DateTime<Utc> {
    Utc::now() + chrono::Duration::days(REFRESH_TOKEN_TTL_DAYS)
}
