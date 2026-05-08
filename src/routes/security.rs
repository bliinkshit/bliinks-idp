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
    helpers::{get_user_ctx, base_url_from_headers},
    render::render,
    routes::{auth::USER_SESSION_KEY, avatar::AVATAR_DIR},
    session::{clear_cookies, Session},
    AppState,
    render_err,
};

pub async fn render_security(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    if session.get::<String>(USER_SESSION_KEY).is_none() {
        return Ok(Redirect::to("/auth/login").into_response());
    }

    let mut ctx = Context::new();
    ctx.insert("title", "Security");
    get_user_ctx(&state.pool, &session, &mut ctx).await;

    render(&state.tera, "security.html", &mut ctx, start)
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
    let start = Instant::now();

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("title", "Security");

    let user = get_user_by_id(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    ctx.insert("auth_username",     &user.username);
    ctx.insert("auth_is_admin",     &user.admin);
    ctx.insert("auth_display_name", &user.display_name);
    ctx.insert("auth_color",        &user.color);

    let parsed = PasswordHash::new(&user.password)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        render_err!(state, "security.html", ctx, "Incorrect password.", start);
    }

    let base_url  = base_url_from_headers(&headers);
    let reset_url = issue_password_reset(&state.pool, &user_id, &base_url)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert("reset_url", &reset_url);

    render(&state.tera, "security.html", &mut ctx, start)
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
    let start = Instant::now();

    let secure = !crate::cfg::CONFIG.general.dev;

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("title", "Security");

    let user = get_user_by_id(&state.pool, &user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    ctx.insert("auth_username",     &user.username);
    ctx.insert("auth_is_admin",     &user.admin);
    ctx.insert("auth_display_name", &user.display_name);
    ctx.insert("auth_color",        &user.color);

    let parsed = PasswordHash::new(&user.password)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        render_err!(state, "security.html", ctx, "Incorrect password.", start);
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
