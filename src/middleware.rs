// src/middleware.rs
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use crate::{
    db::queries::get_user_by_username,
    session::Session,
    routes::auth::USER_SESSION_KEY,
    AppState,
};

pub async fn require_auth(
    session:      Session,
    req:          Request,
    next:         Next,
) -> Response {
    if session.get::<String>(USER_SESSION_KEY).is_some() {
        return next.run(req).await;
    }
    Redirect::to("/auth/login").into_response()
}

pub async fn redirect_if_authed(
    session:      Session,
    req:          Request,
    next:         Next,
) -> Response {
    if session.get::<String>(USER_SESSION_KEY).is_none() {
        return next.run(req).await;
    }
    Redirect::to("/").into_response()
}

pub async fn require_admin(
    session:        Session,
    State(state):   State<Arc<AppState>>,
    req:            Request,
    next:           Next,
) -> Response {
    let user_id = match session.get::<String>(USER_SESSION_KEY) {
        Some(id) => id,
        None => return Redirect::to("/auth/login").into_response(),
    };

    let user = match get_user_by_username(&state.pool, &user_id).await {
        Ok(Some(u)) => u,
        _ => return Redirect::to("/auth/login").into_response(),
    };

    if !user.admin {
        return (axum::http::StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    next.run(req).await
}
