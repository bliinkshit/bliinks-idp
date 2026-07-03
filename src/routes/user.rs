// src/routes/user.rs
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use tera::Context;

// internal
use crate::{
    db::queries::get_user_by_username,
    error::{AppError, AppErrorResponse},
    helpers::get_user_ctx,
    render::render,
    routes::error::render_error,
    session::Session,
    AppState,
};

pub async fn render_profile(
    session:        Session,
    State(state):   State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    let user = match get_user_by_username(&state.pool, &username).await {
        Ok(Some(u)) if !u.is_deleted() => u,
        Ok(_)  => return Ok(render_error(State(Arc::clone(&state)), session, AppError::NotFound).await.into_response()),
        Err(e) => return Ok(render_error(State(Arc::clone(&state)), session, e).await.into_response()),
    };

    let mut ctx = Context::new();
    ctx.insert("profile_id",           &user.id.to_string());
    ctx.insert("profile_username",     &user.username);
    ctx.insert("profile_display_name", &user.display_name);
    ctx.insert("profile_color",        &user.color);
    ctx.insert("profile_avatar",       &user.avatar_updated_at.is_some());
    ctx.insert("profile_date_created", &user.date_created);
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;

    render(&state.tera, "profile.html", &mut ctx, start)
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
