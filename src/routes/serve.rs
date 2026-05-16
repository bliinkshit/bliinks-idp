// src/routes/serve.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tower::util::ServiceExt;

use crate::error::AppError;
use crate::session::Session;
use crate::AppState;

pub async fn static_or_error(
    State(state): State<Arc<AppState>>,
    session:      Session,
    req:          axum::extract::Request,
) -> axum::response::Response {
    let path = req.uri().path();

    if path != "/" && path.ends_with('/') {
        let trimmed = path.trim_end_matches('/');
        return Redirect::permanent(trimmed).into_response();
    }

    match ServeDir::new("static").oneshot(req).await {
        Ok(res) if res.status() != StatusCode::NOT_FOUND => res.into_response(),
        _ => crate::routes::error::render_error(State(state), session, AppError::NotFound)
            .await
            .into_response(),
    }
}
