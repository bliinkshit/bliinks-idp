// src/routes/index.rs
use std::time::Instant;
use std::sync::Arc;

use axum::{
    extract::State,
    response::Html,
};
use tera::Context;

use crate::{
    error::AppErrorResponse,
    render::render,
    AppState,
};

pub async fn render_index(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    let start = Instant::now();
    let mut ctx = Context::new();

    render(&state.tera, "index.html", &mut ctx, start)
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
