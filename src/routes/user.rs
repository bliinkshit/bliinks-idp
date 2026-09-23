// src/routes/user.rs
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use tera::Context;
use uuid::Uuid;

// internal
use crate::{
    db::queries::{get_user_by_id, get_user_by_username},
    error::{AppError, AppErrorResponse},
    helpers::get_user_ctx,
    render::render,
    routes::{auth::USER_SESSION_KEY, error::render_error},
    session::Session,
    AppState,
};

pub async fn render_redirect(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Redirect {
    let Some(user_id_str) = session.get::<String>(USER_SESSION_KEY) else {
        return Redirect::to("/auth/login");
    };
    let Ok(user_id) = user_id_str.parse::<Uuid>() else {
        return Redirect::to("/auth/login");
    };
    let Ok(Some(user)) = get_user_by_id(&state.pool, user_id).await else {
        return Redirect::to("/auth/login");
    };

    Redirect::to(&format!("/@{}", user.username))
}

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
