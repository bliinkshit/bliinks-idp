// src/routes/error.rs
use std::sync::Arc;

use axum::{extract::State, response::{Html, IntoResponse}};
use tera::Context;

use crate::{
    error::{AppError, AppErrorResponse},
    helpers::get_user_ctx,
    render::render,
    session::Session,
    AppState,
};

pub async fn render_error(
    State(state): State<Arc<AppState>>,
    session:      Session,
    err:          AppError,
) -> impl IntoResponse {
    let status = err.status();

    let mut ctx = Context::new();
    ctx.insert("code",  &status.as_u16());
    ctx.insert("error", &err.message());
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;

    match render(&state.tera, "error.html", &mut ctx, std::time::Instant::now()) {
        Ok(body) => (status, Html(body)).into_response(),
        Err(e)   => AppErrorResponse(state, e).into_response(),
    }
}
