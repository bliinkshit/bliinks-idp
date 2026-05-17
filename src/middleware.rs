// src/middleware.rs
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use governor::middleware::StateInformationMiddleware;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use tower_http::timeout::TimeoutLayer;

// internal
use crate::{
    db::queries::get_user_by_id,
    error::{AppError, AppErrorResponse},
    helpers::get_user_ctx,
    render::render,
    routes::auth::USER_SESSION_KEY,
    session::Session,
    AppState,
};

pub fn auth_rate_limiter() -> GovernorLayer<SmartIpKeyExtractor, StateInformationMiddleware> {
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(5)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );
    GovernorLayer { config }
}

pub fn api_rate_limiter() -> GovernorLayer<SmartIpKeyExtractor, StateInformationMiddleware> {
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(30)
            .key_extractor(SmartIpKeyExtractor)
            .use_headers()
            .finish()
            .unwrap(),
    );
    GovernorLayer { config }
}

pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();

    h.insert("X-Content-Type-Options",  "nosniff".parse().unwrap());
    h.insert("X-Frame-Options",         "DENY".parse().unwrap());
    h.insert("X-XSS-Protection",        "1; mode=block".parse().unwrap());
    h.insert("Referrer-Policy",         "strict-origin-when-cross-origin".parse().unwrap());
    h.insert("Permissions-Policy",      "geolocation=(), microphone=(), camera=()".parse().unwrap());
    h.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
            .parse()
            .unwrap(),
    );

    if !cfg!(debug_assertions) {
        h.insert(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload".parse().unwrap(),
        );
    }

    res
}

pub async fn require_auth(session: Session, req: Request, next: Next) -> Response {
    if session.get::<String>(USER_SESSION_KEY).is_some() {
        return next.run(req).await;
    }
    Redirect::to("/auth/login").into_response()
}

pub async fn redirect_if_authed(session: Session, req: Request, next: Next) -> Response {
    if session.get::<String>(USER_SESSION_KEY).is_none() {
        return next.run(req).await;
    }
    Redirect::to("/").into_response()
}

pub async fn require_admin(
    session:      Session,
    State(state): State<Arc<AppState>>,
    req:          Request,
    next:         Next,
) -> Response {
    let user_id = match session.get::<String>(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Redirect::to("/auth/login").into_response(),
    };

    let user = match get_user_by_id(&state.pool, &user_id).await {
        Ok(Some(u)) => u,
        _           => return Redirect::to("/auth/login").into_response(),
    };

    if !state.roles.has_by_id(&user.role, "access_admin") {
        let err    = AppError::Forbidden;
        let status = err.status();
        let mut ctx = tera::Context::new();
        ctx.insert("code",  &status.as_u16());
        ctx.insert("error", &err.message());
        get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
        return match render(&state.tera, "error.html", &mut ctx, std::time::Instant::now()) {
            Ok(body) => (status, axum::response::Html(body)).into_response(),
            Err(e)   => AppErrorResponse(state, e).into_response(),
        };
    }

    next.run(req).await
}

pub fn timeout_layer() -> TimeoutLayer {
    TimeoutLayer::new(std::time::Duration::from_secs(30))
}
