// src/routes/avatar.rs
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::fs;
use uuid::Uuid;

// internal
use crate::{
    db::queries::get_user_by_id,
    AppState,
};

pub const AVATAR_DIR: &str = "uploads/avatars";

pub async fn handle_serve(
    Path(user_id_str): Path<String>,
    State(state):      State<Arc<AppState>>,
    headers:           HeaderMap,
) -> Response {
    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let user = match get_user_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => u,
        _           => return StatusCode::NOT_FOUND.into_response(),
    };

    let updated_at = match user.avatar_updated_at {
        Some(ts) => ts,
        None     => return StatusCode::NOT_FOUND.into_response(),
    };

    let etag = format!("\"{}\"", updated_at.timestamp_millis());

    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm == etag {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }

    let path = format!("{}/{}.gif", AVATAR_DIR, user_id);
    let data = match fs::read(&path).await {
        Ok(d)  => d,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE,  "image/gif")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG,          etag)
        .body(Body::from(data))
        .unwrap()
}
