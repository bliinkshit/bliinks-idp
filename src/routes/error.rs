// src/routes/error.rs
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};

use crate::{error::{AppError, AppErrorResponse}, AppState};

pub async fn render_error(
    State(state): State<Arc<AppState>>,
    err: AppError,
) -> impl IntoResponse {
    AppErrorResponse(state, err).into_response()
}
