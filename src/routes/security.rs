// src/routes/security.rs
use std::sync::Arc;
use std::time::Instant;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use tera::Context;
use tokio::fs;

use crate::{
    db::{
        oauth_queries::revoke_all_tokens_for_user,
        queries::{delete_sessions_for_user, delete_user, get_user_by_id, issue_password_reset},
    },
    error::{AppError, AppErrorResponse},
    render::render,
    routes::{auth::USER_SESSION_KEY, avatar::AVATAR_DIR},
    session::{clear_cookies, Session},
    AppState,
};

fn base_url_from_headers(headers: &HeaderMap) -> String {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{}://{}", scheme, host)
}

fn base_ctx() -> Context {
    let mut ctx = Context::new();
    ctx.insert("title", "Security");
    ctx
}

macro_rules! render_err {
    ($state:expr, $ctx:expr, $msg:expr) => {{
        $ctx.insert("error", $msg);
        let html = render(&$state.tera, "security.html", &mut $ctx, Instant::now())
            .map_err(|e| AppErrorResponse(Arc::clone(&$state), e))?;
        return Ok(Html(html).into_response());
    }};
}

pub async fn render_security(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    if session.get::<String>(USER_SESSION_KEY).is_none() {
        return Ok(Redirect::to("/auth/login").into_response());
    }

    render(&state.tera, "security.html", &mut base_ctx(), Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct ResetForm {
    pub password: String,
}

pub async fn handle_reset(
    session:      Session,
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
    Form(form):   Form<ResetForm>,
) -> Result<Response, AppErrorResponse> {
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let mut ctx = base_ctx();

    let user = get_user_by_id(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    let parsed = PasswordHash::new(&user.password)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        render_err!(state, ctx, "Incorrect password.");
    }

    let base_url  = base_url_from_headers(&headers);
    let reset_url = issue_password_reset(&state.pool, &user_id, &base_url)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert("reset_url", &reset_url);

    render(&state.tera, "security.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct DeleteAccountForm {
    pub password: String,
}

pub async fn handle_delete_account(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<DeleteAccountForm>,
) -> Result<Response, AppErrorResponse> {
    let secure = !crate::cfg::CONFIG.general.dev;

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let mut ctx = base_ctx();

    let user = get_user_by_id(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    let parsed = PasswordHash::new(&user.password)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        render_err!(state, ctx, "Incorrect password.");
    }

    delete_user(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    delete_sessions_for_user(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    revoke_all_tokens_for_user(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let _ = fs::remove_file(format!("{}/{}.gif", AVATAR_DIR, user_id)).await;

    session.destroy().await;

    Ok((
        clear_cookies(secure),
        Redirect::to("/auth/login"),
    ).into_response())
}
