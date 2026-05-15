// src/routes/index.rs
use std::time::Instant;
use std::sync::Arc;

use axum::{
    extract::State,
    response::Html,
};
use tera::Context;

// internal
use crate::{
    error::AppErrorResponse,
    render::render,
    AppState,
    session::Session,
    helpers::get_user_ctx,
};

pub async fn render_index(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    let start = Instant::now();
    let mut ctx = Context::new();

    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;

    render(&state.tera, "index.html", &mut ctx, start)
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
