// src/routes/settings.rs
use std::sync::Arc;
use std::time::Instant;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use tera::Context;

use crate::{
    db::queries::{
        get_user_by_id, issue_password_reset, update_user_color, update_user_display_name,
    },
    error::{AppError, AppErrorResponse},
    render::render,
    routes::auth::USER_SESSION_KEY,
    session::Session,
    AppState,
};

const MAX_DISPLAY_NAME_LEN: usize = 64;

fn is_valid_hex_color(s: &str) -> bool {
    let s = s.strip_prefix('#').unwrap_or(s);
    (s.len() == 6 || s.len() == 3) && s.chars().all(|c| c.is_ascii_hexdigit())
}

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

macro_rules! render_err {
    ($state:expr, $ctx:expr, $msg:expr) => {{
        $ctx.insert("error", $msg);
        let html = render(&$state.tera, "settings.html", &mut $ctx, Instant::now())
            .map_err(|e| AppErrorResponse(Arc::clone(&$state), e))?;
        return Ok(Html(html).into_response());
    }};
}

async fn settings_ctx(
    state:   &Arc<AppState>,
    user_id: &str,
) -> Result<(Context, crate::db::models::User), AppErrorResponse> {
    let user = get_user_by_id(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(state), AppError::Internal("User not found".into())))?;

    let mut ctx = Context::new();
    ctx.insert("title",        "Settings");
    ctx.insert("username",     &user.username);
    ctx.insert("display_name", &user.display_name);
    ctx.insert("color",        &user.color);
    Ok((ctx, user))
}

pub async fn render_settings(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = settings_ctx(&state, &user_id).await?;

    render(&state.tera, "settings.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct DisplayNameForm {
    pub display_name: String,
}

pub async fn handle_display_name(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<DisplayNameForm>,
) -> Result<Response, AppErrorResponse> {
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = settings_ctx(&state, &user_id).await?;

    let name = form.display_name.trim();

    if name.len() > MAX_DISPLAY_NAME_LEN {
        render_err!(state, ctx, "Display name must be 64 characters or fewer.");
    }

    let value = if name.is_empty() { None } else { Some(name) };

    update_user_display_name(&state.pool, &user_id, value)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert("display_name", &value);
    ctx.insert("success_profile", "Display name updated.");

    render(&state.tera, "settings.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct ColorForm {
    pub color: String,
}

pub async fn handle_color(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<ColorForm>,
) -> Result<Response, AppErrorResponse> {
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = settings_ctx(&state, &user_id).await?;

    let color = form.color.trim();

    let value = if color.is_empty() {
        None
    } else {
        if !is_valid_hex_color(color) {
            render_err!(state, ctx, "Color must be a valid hex value (e.g. #ff6b6b).");
        }
        let normalized = format!("#{}", color.strip_prefix('#').unwrap_or(color).to_lowercase());
        Some(normalized)
    };

    update_user_color(&state.pool, &user_id, value.as_deref())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert("color",         &value);
    ctx.insert("success_color", "Color updated.");

    render(&state.tera, "settings.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct SettingsResetForm {
    pub password: String,
}

pub async fn handle_reset(
    session:      Session,
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
    Form(form):   Form<SettingsResetForm>,
) -> Result<Response, AppErrorResponse> {
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, user) = settings_ctx(&state, &user_id).await?;

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

    render(&state.tera, "settings.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
