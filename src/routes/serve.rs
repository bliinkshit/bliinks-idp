// src/routes/serve.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tower_http::services::ServeDir;

use crate::error::AppError;
use crate::AppState;

pub async fn static_or_error(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use tower::util::ServiceExt;
    match ServeDir::new("static").oneshot(req).await {
        Ok(res) if res.status() != StatusCode::NOT_FOUND => res.into_response(),
        _ => crate::routes::error::render_error(State(state), AppError::NotFound)
            .await
            .into_response(),
    }
}