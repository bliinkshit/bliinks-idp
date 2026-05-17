// src/helpers.rs
use sqlx::SqlitePool;
use tera::Context;
use axum::http::HeaderMap;

// internal
use crate::{
    db::{models::User, queries::get_user_by_id},
    rbac::RoleCache,
    routes::auth::USER_SESSION_KEY,
    session::Session,
};

pub async fn get_user_ctx(pool: &SqlitePool, roles: &RoleCache, session: &Session, ctx: &mut Context) {
    let Some(user_id) = session.get::<String>(USER_SESSION_KEY) else {
        ctx.insert("auth_username",     &Option::<String>::None);
        ctx.insert("auth_role",         &"");
        ctx.insert("auth_display_name", &Option::<String>::None);
        ctx.insert("auth_color",        &Option::<String>::None);
        return;
    };
    let Ok(Some(user)) = get_user_by_id(pool, &user_id).await else {
        ctx.insert("auth_username",     &Option::<String>::None);
        ctx.insert("auth_role",         &"");
        ctx.insert("auth_display_name", &Option::<String>::None);
        ctx.insert("auth_color",        &Option::<String>::None);
        return;
    };
    let role_name = roles.name_for_id(&user.role).unwrap_or_default();
    ctx.insert("auth_username",     &user.username);
    ctx.insert("auth_role",         &role_name);
    ctx.insert("auth_display_name", &user.display_name);
    ctx.insert("auth_color",        &user.color);
}

pub fn insert_user_ctx(ctx: &mut Context, user: &User, roles: &RoleCache) {
    let role_name = roles.name_for_id(&user.role).unwrap_or_default();
    ctx.insert("auth_username",     &user.username);
    ctx.insert("auth_role",         &role_name);
    ctx.insert("auth_display_name", &user.display_name);
    ctx.insert("auth_color",        &user.color);
}

pub fn base_url_from_headers(headers: &HeaderMap) -> String {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{}://{}", scheme, host)
}

// to be renamed: render_client_error
#[macro_export]
macro_rules! render_err {
    ($state:expr, $template:expr, $ctx:expr, $msg:expr, $start:expr) => {{
        $ctx.insert("error", $msg);
        let html = $crate::render::render(&$state.tera, $template, &mut $ctx, $start)
            .map_err(|e| $crate::error::AppErrorResponse(Arc::clone(&$state), e))?;
        return Ok(axum::response::IntoResponse::into_response(axum::response::Html(html)));
    }};
}

#[macro_export]
macro_rules! render_server_error {
    ($result:expr, $state:expr, $session:expr) => {
        match $result {
            Ok(v)  => v,
            Err(e) => return Ok($crate::routes::error::render_error(
                axum::extract::State(Arc::clone(&$state)),
                $session,
                $crate::error::AppError::Internal(e.to_string()),
            ).await.into_response()),
        }
    };
}

pub fn validate_password(password: &str, password_repeat: &str) -> Result<(), &'static str> {
    if password.len() < 6 {
        return Err("Password must be at least 6 characters.");
    }

    if password != password_repeat {
        return Err("Passwords do not match.");
    }

    Ok(())
}
