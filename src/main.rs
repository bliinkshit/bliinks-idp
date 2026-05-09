// src/main.rs
mod cfg;
mod db;
mod error;
mod middleware;
mod oauth;
mod render;
mod routes;
mod session;
mod helpers;

use axum::{
    extract::{DefaultBodyLimit, Request},
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use tera::Tera;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};
use std::net::SocketAddr;

//internal
use cfg::CONFIG;
use db::init_pool;
use error::AppError;
use session::delete_expired;
use db::queries::delete_expired_password_resets;

pub struct AppState {
    pub tera: Tera,
    pub pool: SqlitePool,
}

async fn inject_pool(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    mut req: Request,
    next: axum_middleware::Next,
) -> axum::response::Response {
    req.extensions_mut().insert(state.pool.clone());
    next.run(req).await
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    fmt().with_env_filter(EnvFilter::new("bliinks_idp=debug,tower_http=debug")).init();

    if CONFIG.general.dev {
        warn!("DEV_MODE is enabled");
    }

    let pool  = init_pool(&CONFIG.database.url).await?;
    let tera  = Tera::new("templates/**/*")?;
    let state = Arc::new(AppState { tera, pool });
    let pool  = state.pool.clone();

    let cleanup_pool = state.pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            delete_expired(&cleanup_pool).await;
            delete_expired_password_resets(&cleanup_pool).await;
            db::oauth_queries::delete_expired_oauth(&cleanup_pool).await;
        }
    });

    let guest_routes = Router::new()
        .route("/auth/register", get(routes::auth::render_register))
        .route("/auth/register", post(routes::auth::handle_register))
        .route("/auth/login",    get(routes::auth::render_login))
        .route("/auth/login",    post(routes::auth::handle_login))
        .route("/captcha",       get(routes::captcha::render_captcha))
        .layer(middleware::auth_rate_limiter())
        .layer(axum_middleware::from_fn(middleware::redirect_if_authed));

    let admin_routes = Router::new()
        .route("/admin",                get(routes::admin::render_admin))
        .route("/admin/approve",        post(routes::admin::handle_approve))
        .route("/admin/toggle-admin",   post(routes::admin::handle_toggle_admin))
        .route("/admin/reset",          post(routes::admin::handle_issue_reset))
        .route("/admin/delete", post(routes::admin::handle_force_delete))
        .route("/admin/clients/create", post(routes::admin::handle_create_client))
        .route("/admin/clients/delete", post(routes::admin::handle_delete_client))
        .layer(axum_middleware::from_fn_with_state(state.clone(), middleware::require_admin));

    let protected_routes = Router::new()
        .route("/auth/logout",           get(routes::auth::handle_logout))
        .route("/settings",              get(routes::settings::render_settings))
        .route("/settings/display-name", post(routes::settings::handle_display_name))
        .route("/settings/color",        post(routes::settings::handle_color))
        .route("/settings/avatar",       post(routes::avatar::handle_upload))
        .route("/security",              get(routes::security::render_security))
        .route("/security/reset",        post(routes::security::handle_reset))
        .route("/security/delete",       post(routes::security::handle_delete_account))
        .route("/security/revoke-client", post(routes::security::handle_revoke_client))
        .layer(axum_middleware::from_fn(middleware::require_auth));

    let oauth_routes = Router::new()
        .route("/oauth/authorize",    get(routes::oauth::render_authorize))
        .route("/oauth/authorize",    post(routes::oauth::handle_authorize))
        .route("/oauth/token",        post(routes::oauth::handle_token))
        .route("/oauth/token/revoke", post(routes::oauth::handle_revoke))
        .route("/oauth/userinfo",     get(routes::oauth::handle_userinfo))
        .layer(middleware::api_rate_limiter());

    let app = Router::new()
        .route("/",                      get(routes::index::render_index))
        .route("/auth",             get(routes::auth::render_redirect))
        .route("/auth/reset",       get(routes::auth::render_reset))
        .route("/auth/reset",       post(routes::auth::handle_reset))
        .route("/avatars/:user_id", get(routes::avatar::handle_serve))
        .merge(guest_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .merge(oauth_routes)
        .fallback(routes::serve::static_or_error)
        .layer(DefaultBodyLimit::max(5 * 1024 * 1024))
        .layer(axum_middleware::from_fn(middleware::security_headers))
        .layer(axum_middleware::from_fn_with_state(state.clone(), inject_pool))
        .with_state(state);

    let app = if CONFIG.general.dev {
        app.layer(TraceLayer::new_for_http())
    } else {
        app
    };

    let listener = tokio::net::TcpListener::bind(CONFIG.server.addr()).await?;
    info!("listening on http://{}", CONFIG.server.addr());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received, draining connections...");
        })
        .await?;

    info!("closing database pool...");
    pool.close().await;
    info!("goodbye~");

    Ok(())
}
