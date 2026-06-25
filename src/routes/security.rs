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
use uuid::Uuid;

// internal
use crate::{
    db::{
        oauth_queries::{get_connected_clients_for_user, revoke_all_tokens_for_user, revoke_tokens_for_user_and_client},
        queries::{
            create_invite, delete_sessions_for_user, delete_user,
            get_invites_by_issuer, get_user_by_id, issue_password_reset,
        },
    },
    error::{AppError, AppErrorResponse},
    helpers::{get_user_ctx, base_url_from_headers, insert_user_ctx},
    render::render,
    routes::{auth::USER_SESSION_KEY, avatar::AVATAR_DIR},
    session::{clear_cookies, Session},
    AppState,
    render_err,
};

pub async fn render_security(
    session:      Session,
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let clients_raw = get_connected_clients_for_user(&state.pool, user_id)
        .await
        .unwrap_or_default();

    let clients: Vec<_> = clients_raw.into_iter().map(|c| serde_json::json!({
        "id":   c.id.to_string(),
        "name": c.name,
    })).collect();

    let invites_raw = get_invites_by_issuer(&state.pool, user_id)
        .await
        .unwrap_or_default();

    let base_url = base_url_from_headers(&headers);
    let invites: Vec<_> = invites_raw.iter().map(|inv| serde_json::json!({
        "url":        format!("{}/auth/register?invite={}", base_url, inv.code),
        "used":       inv.recipient_id.is_some(),
        "created_at": inv.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
    })).collect();

    let mut ctx = Context::new();
    ctx.insert("title",             "Security");
    ctx.insert("connected_clients", &clients);
    ctx.insert("invites",           &invites);
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;

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

    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("title", "Security");

    let user = get_user_by_id(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    insert_user_ctx(&mut ctx, &user, &state.roles);

    let password      = form.password.clone();
    let password_hash = user.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&password_hash)
            .ok()
            .and_then(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).ok())
            .is_some()
    })
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if !verified {
        render_err!(state, "security.html", ctx, "Incorrect password.", start);
    }

    let base_url  = base_url_from_headers(&headers);
    let reset_url = issue_password_reset(&state.pool, user_id, &base_url)
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
    let start  = Instant::now();
    let secure = !crate::cfg::CONFIG.general.dev;

    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("title", "Security");

    let user = get_user_by_id(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    insert_user_ctx(&mut ctx, &user, &state.roles);

    let password      = form.password.clone();
    let password_hash = user.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&password_hash)
            .ok()
            .and_then(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).ok())
            .is_some()
    })
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if !verified {
        render_err!(state, "security.html", ctx, "Incorrect password.", start);
    }

    let deleted_role_id = state.roles.id_for_name("deleted")
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("RBAC: deleted role not found in cache.".into())))?;

    delete_user(&state.pool, user_id, deleted_role_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    delete_sessions_for_user(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    revoke_all_tokens_for_user(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let _ = fs::remove_file(format!("{}/{}.gif", AVATAR_DIR, user_id)).await;

    session.destroy().await;

    Ok((clear_cookies(secure), Redirect::to("/auth/login")).into_response())
}

#[derive(Deserialize)]
pub struct RevokeClientForm {
    pub client_id: String,
}

pub async fn handle_revoke_client(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<RevokeClientForm>,
) -> Result<Response, AppErrorResponse> {
    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let client_id = match form.client_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/security").into_response()),
    };

    revoke_tokens_for_user_and_client(&state.pool, user_id, client_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    Ok(Redirect::to("/security").into_response())
}

pub async fn handle_create_invite(
    session:      Session,
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
) -> Result<Response, AppErrorResponse> {
    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let code = {
        use rand::RngCore;
        use argon2::password_hash::rand_core::OsRng;
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        hex::encode(raw)
    };

    create_invite(&state.pool, Uuid::new_v4(), &code, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    Ok(Redirect::to("/security").into_response())
}
