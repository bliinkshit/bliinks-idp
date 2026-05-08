// src/routes/settings.rs
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use tera::Context;

//internal
use crate::{
    db::{models::User, queries::{get_user_by_id, update_user_color, update_user_display_name}},
    error::{AppError, AppErrorResponse},
    render::render,
    routes::auth::USER_SESSION_KEY,
    session::Session,
    AppState,
    helpers::insert_user_ctx,
    render_err,
};

const MAX_DISPLAY_NAME_LEN: usize = 64;

fn is_valid_hex_color(s: &str) -> bool {
    let s = s.strip_prefix('#').unwrap_or(s);
    (s.len() == 6 || s.len() == 3) && s.chars().all(|c| c.is_ascii_hexdigit())
}

async fn settings_ctx(
    state:   &Arc<AppState>,
    user_id: &str,
) -> Result<(Context, User), AppErrorResponse> {
    let user = get_user_by_id(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(state), AppError::Internal("User not found".into())))?;

    let mut ctx = Context::new();
    ctx.insert("title",        "Settings");
    ctx.insert("id",           &user.id);
    ctx.insert("avatar",       &user.avatar_updated_at.is_some());
    ctx.insert("username",     &user.username);
    ctx.insert("display_name", &user.display_name);
    ctx.insert("color",        &user.color);
    insert_user_ctx(&mut ctx, &user);

    Ok((ctx, user))
}

pub async fn render_settings(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();
    
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = settings_ctx(&state, &user_id).await?;

    render(&state.tera, "settings.html", &mut ctx, start)
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
    let start = Instant::now();

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = settings_ctx(&state, &user_id).await?;

    let name = form.display_name.trim();

    if name.len() > MAX_DISPLAY_NAME_LEN {
        render_err!(state, "settings.html", ctx, "Display name must be 64 characters or fewer.", start);
    }

    let value = if name.is_empty() { None } else { Some(name) };

    update_user_display_name(&state.pool, &user_id, value)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert("display_name",   &value);
    ctx.insert("success_profile", "Display name updated.");

    render(&state.tera, "settings.html", &mut ctx, start)
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
    let start = Instant::now();

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
            render_err!(state, "settings.html", ctx, "Color must be a valid hex value (e.g. #ff6b6b).", start);
        }
        let normalized = format!("#{}", color.strip_prefix('#').unwrap_or(color).to_lowercase());
        Some(normalized)
    };

    update_user_color(&state.pool, &user_id, value.as_deref())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert("color",         &value);
    ctx.insert("success_color", "Color updated.");

    render(&state.tera, "settings.html", &mut ctx, start)
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
