// src/session.rs
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, HeaderMap, HeaderValue},
    response::{AppendHeaders, IntoResponse, Response},
};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

pub const COOKIE_NAME: &str = "sid";
const REMEMBER_COOKIE_NAME: &str = "remember";
const SESSION_TTL_SECS:          i64 = 2  * 3600;
const REMEMBER_TTL_SECS:         i64 = 30 * 24 * 3600;
const REMEMBER_REFRESH_THRESHOLD: f64 = 0.8;

#[derive(Debug, Clone)]
pub struct Session {
    pub id:       String,
    pub data:     HashMap<String, Value>,
    pub remember: bool,
    pub user_id:  Option<Uuid>,
    pool:         PgPool,
    is_new:       bool,
    dirty:        bool,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl Session {
    pub async fn load_or_create(
        pool:     &PgPool,
        sid:      Option<&str>,
        remember: bool,
    ) -> Self {
        if let Some(id) = sid {
            if let Ok(Some(row)) = sqlx::query_as::<_, (String, String, Option<Uuid>, i64)>(
                "SELECT id, data, user_id, expires_at
                 FROM sessions
                 WHERE id = $1 AND expires_at > $2"
            )
            .bind(id)
            .bind(now_unix())
            .fetch_optional(pool)
            .await
            {
                let data = serde_json::from_str::<HashMap<String, Value>>(&row.1)
                    .unwrap_or_default();

                info!("loaded session {}", row.0);

                let mut session = Self {
                    id:      row.0,
                    data,
                    remember,
                    user_id: row.2,
                    pool:    pool.clone(),
                    is_new:  false,
                    dirty:   false,
                };

                if remember {
                    let expires_at = row.3;
                    let remaining  = expires_at - now_unix();

                    let refresh_when_less_than =
                        (REMEMBER_TTL_SECS as f64 * REMEMBER_REFRESH_THRESHOLD) as i64;

                    if remaining < refresh_when_less_than {
                        session.dirty = true;
                        session.save().await;
                    }
                }

                return session;
            }
        }

        let id = Uuid::new_v4().to_string();

        info!("creating new session {}", id);

        Self {
            id,
            data:     HashMap::new(),
            remember,
            user_id:  None,
            pool:     pool.clone(),
            is_new:   true,
            dirty:    false,
        }
    }

    pub fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.data.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn insert<T: serde::Serialize>(&mut self, key: &str, value: T) {
        self.data.insert(key.to_string(), serde_json::to_value(value).unwrap());
        self.dirty = true;
    }

    pub fn remove(&mut self, key: &str) {
        if self.data.remove(key).is_some() {
            self.dirty = true;
        }
    }

    pub async fn save(&self) {
        if !self.dirty && !self.is_new {
            return;
        }
        let ttl = if self.remember { REMEMBER_TTL_SECS } else { SESSION_TTL_SECS };
        self.save_with_ttl(ttl).await;
    }

    async fn save_with_ttl(&self, secs: i64) {
        let data    = serde_json::to_string(&self.data).unwrap_or_else(|_| "{}".into());
        let expires = now_unix() + secs;

        info!(
            "saving session {} remember={} expires={}",
            self.id,
            self.remember,
            expires
        );

        if let Err(e) = sqlx::query(
            "INSERT INTO sessions (id, data, user_id, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET
                data       = EXCLUDED.data,
                user_id    = EXCLUDED.user_id,
                expires_at = EXCLUDED.expires_at",
        )
        .bind(&self.id)
        .bind(&data)
        .bind(&self.user_id)
        .bind(expires)
        .execute(&self.pool)
        .await
        {
            warn!("failed to save session {}: {}", self.id, e);
        }
    }

    pub async fn regenerate(&mut self) {
        let old_id  = self.id.clone();
        self.id     = Uuid::new_v4().to_string();
        self.is_new = true;
        self.dirty  = true;

        if let Err(e) = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&old_id)
            .execute(&self.pool)
            .await
        {
            warn!("failed to delete old session {}: {}", old_id, e);
        }

        self.save().await;
    }

    pub async fn destroy(&self) {
        if let Err(e) = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&self.id)
            .execute(&self.pool)
            .await
        {
            warn!("failed to destroy session {}: {}", self.id, e);
        }
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
        let max_age_secs = REMEMBER_TTL_SECS;
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

pub async fn delete_expired(pool: &PgPool) {
    if let Err(e) = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
        .bind(now_unix())
        .execute(pool)
        .await
    {
        warn!("failed to delete expired sessions: {}", e);
    }
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let part   = part.trim();
        let (k, v) = part.split_once('=')?;
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
                .get::<PgPool>()
                .cloned()
                .ok_or(SessionRejection)?;

            let sid      = extract_cookie(&parts.headers, COOKIE_NAME);
            let remember = extract_cookie(&parts.headers, REMEMBER_COOKIE_NAME).is_some();

            Ok(Session::load_or_create(&pool, sid.as_deref(), remember).await)
        })
    }
}
