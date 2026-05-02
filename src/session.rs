// src/session.rs
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, HeaderValue},
    response::{AppendHeaders, IntoResponse, Response},
};
use chrono::Utc;
use serde_json::Value;
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

pub const COOKIE_NAME: &str = "sid";
const REMEMBER_COOKIE_NAME: &str = "remember";
const SESSION_TTL_HOURS: i64    = 2;
const REMEMBER_TTL_DAYS: i64    = 30;

#[derive(Debug, Clone)]
pub struct Session {
    pub id:       String,
    pub data:     HashMap<String, Value>,
    pub remember: bool,
    pool:         SqlitePool,
    is_new:       bool,
}

impl Session {
    pub async fn load_or_create(
        pool:     &SqlitePool,
        sid:      Option<&str>,
        remember: bool,
    ) -> Self {
        if let Some(id) = sid {
            let ttl_hours = if remember { REMEMBER_TTL_DAYS * 24 } else { SESSION_TTL_HOURS };

            if let Ok(Some(row)) = sqlx::query_as::<_, (String, String)>(
                "SELECT id, data FROM sessions WHERE id = ? AND expires_at > ?",
            )
            .bind(id)
            .bind(Utc::now().to_rfc3339())
            .fetch_optional(pool)
            .await
            {
                let data = serde_json::from_str::<HashMap<String, Value>>(&row.1)
                    .unwrap_or_default();

                let session = Self {
                    id: row.0,
                    data,
                    remember,
                    pool: pool.clone(),
                    is_new: false,
                };

                if remember {
                    session.save_with_ttl(ttl_hours).await;
                }

                return session;
            }
        }

        Self {
            id:       Uuid::new_v4().to_string(),
            data:     HashMap::new(),
            remember: false,
            pool:     pool.clone(),
            is_new:   true,
        }
    }

    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.data.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn insert<T: serde::Serialize>(&mut self, key: &str, value: T) {
        self.data.insert(key.to_string(), serde_json::to_value(value).unwrap());
    }

    pub fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    pub async fn save(&self) {
        let ttl = if self.remember { REMEMBER_TTL_DAYS * 24 } else { SESSION_TTL_HOURS };
        self.save_with_ttl(ttl).await;
    }

    async fn save_with_ttl(&self, hours: i64) {
        let data    = serde_json::to_string(&self.data).unwrap_or_else(|_| "{}".into());
        let expires = (Utc::now() + chrono::Duration::hours(hours)).to_rfc3339();

        let _ = sqlx::query(
            "INSERT INTO sessions (id, data, expires_at)
             VALUES (?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at",
        )
        .bind(&self.id)
        .bind(&data)
        .bind(&expires)
        .execute(&self.pool)
        .await;
    }

    pub async fn regenerate(&mut self) {
        let old_id  = self.id.clone();
        self.id     = Uuid::new_v4().to_string();
        self.is_new = true;

        let _ = sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&old_id)
            .execute(&self.pool)
            .await;

        self.save().await;
    }

    pub async fn destroy(&self) {
        let _ = sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&self.id)
            .execute(&self.pool)
            .await;
    }

    pub fn cookie_header(&self, secure: bool) -> HeaderValue {
        let secure_flag = if secure { "; Secure" } else { "" };
        let val = format!(
            "{}={}; HttpOnly; SameSite=Lax; Path=/{secure_flag}",
            COOKIE_NAME, self.id
        );
        HeaderValue::from_str(&val).unwrap()
    }

    pub fn remember_cookie_header(&self, secure: bool) -> HeaderValue {
        let secure_flag  = if secure { "; Secure" } else { "" };
        let max_age_secs = REMEMBER_TTL_DAYS * 24 * 3600;
        let val = format!(
            "{}=1; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}{secure_flag}",
            REMEMBER_COOKIE_NAME,
        );
        HeaderValue::from_str(&val).unwrap()
    }

    pub fn is_new(&self) -> bool {
        self.is_new
    }
}

pub fn clear_cookies(secure: bool) -> AppendHeaders<[(header::HeaderName, HeaderValue); 2]> {
    let secure_flag = if secure { "; Secure" } else { "" };
    let sid = HeaderValue::from_str(&format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure_flag}",
        COOKIE_NAME,
    )).unwrap();
    let remember = HeaderValue::from_str(&format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure_flag}",
        REMEMBER_COOKIE_NAME,
    )).unwrap();
    AppendHeaders([
        (header::SET_COOKIE, sid),
        (header::SET_COOKIE, remember),
    ])
}

pub async fn delete_expired(pool: &SqlitePool) {
    let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await;
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let part    = part.trim();
        let (k, v)  = part.split_once('=')?;
        if k.trim() == name { Some(v.trim().to_string()) } else { None }
    })
}

pub struct SessionRejection;

impl IntoResponse for SessionRejection {
    fn into_response(self) -> Response {
        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response()
    }
}

impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
{
    type Rejection = SessionRejection;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts:  &'life0 mut Parts,
        _state: &'life1 S,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self:   'async_trait,
    {
        Box::pin(async move {
            let pool = parts
                .extensions
                .get::<SqlitePool>()
                .cloned()
                .ok_or(SessionRejection)?;

            let sid      = extract_cookie(&parts.headers, COOKIE_NAME);
            let remember = extract_cookie(&parts.headers, REMEMBER_COOKIE_NAME).is_some();

            Ok(Session::load_or_create(&pool, sid.as_deref(), remember).await)
        })
    }
}
