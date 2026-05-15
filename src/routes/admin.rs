// src/routes/admin.rs
use std::sync::Arc;
use std::time::Instant;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response, Redirect},
};
use serde::Deserialize;
use tera::Context;
use uuid::Uuid;
use tokio::fs;

// internal
use crate::{
    db::{
        oauth_queries::{
            add_redirect_uri, create_client, delete_client, get_all_clients, revoke_all_tokens_for_user,
        },
        queries::{
            delete_sessions_for_user, delete_user, get_all_users, issue_password_reset, set_user_role,
        },
    },
    error::{AppError, AppErrorResponse},
    render::render,
    AppState,
    session::{clear_cookies, Session},
    routes::avatar::AVATAR_DIR,
    helpers::get_user_ctx,
};

#[derive(Deserialize)]
pub struct SetRoleForm {
    pub user_id: String,
    pub role:    String,
}

#[derive(Deserialize)]
pub struct ResetForm {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct CreateClientForm {
    pub name:         String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct DeleteClientForm {
    pub client_id: String,
}

#[derive(Deserialize)]
pub struct ForceDeleteForm {
    pub user_id: String,
}

fn base_url_from_request(headers: &HeaderMap) -> String {
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

async fn build_ctx(state: &Arc<AppState>) -> Result<Context, AppErrorResponse> {
    let all_users = get_all_users(&state.pool)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(state), e))?;
    let clients = get_all_clients(&state.pool)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(state), e))?;

    let deleted_id = state.roles.id_for_name("deleted").unwrap_or_default();
    let banned_id  = state.roles.id_for_name("banned").unwrap_or_default();
    let pending_id = state.roles.id_for_name("pending").unwrap_or_default();

    let mut pending  = Vec::new();
    let mut active   = Vec::new();
    let mut banned   = Vec::new();
    let mut deleted  = Vec::new();

    for user in all_users {
        if user.role == deleted_id {
            deleted.push(user);
        } else if user.role == banned_id {
            banned.push(user);
        } else if user.role == pending_id {
            pending.push(user);
        } else {
            active.push(user);
        }
    }

    let mut ctx = Context::new();
    ctx.insert("title",   "Admin Panel");
    ctx.insert("pending", &pending);
    ctx.insert("active",  &active);
    ctx.insert("banned",  &banned);
    ctx.insert("deleted", &deleted);
    ctx.insert("clients", &clients);
    Ok(ctx)
}

fn resolve_role_id(state: &Arc<AppState>, role_name: &str) -> Option<String> {
    let allowed = ["pending", "member", "admin", "banned"];
    if !allowed.contains(&role_name) {
        return None;
    }
    state.roles.id_for_name(role_name)
}

pub async fn render_admin(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    let start   = Instant::now();
    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
    render(&state.tera, "admin.html", &mut ctx, start)
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_set_role(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<SetRoleForm>,
) -> Result<Response, AppErrorResponse> {
    let role_id = match resolve_role_id(&state, &form.role) {
        Some(id) => id,
        None     => {
            let mut ctx = build_ctx(&state).await?;
            get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
            ctx.insert("error", "Invalid role.");
            return render(&state.tera, "admin.html", &mut ctx, Instant::now())
                .map(|html| Html(html).into_response())
                .map_err(|e| AppErrorResponse(Arc::clone(&state), e));
        }
    };

    set_user_role(&state.pool, &form.user_id, &role_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    if matches!(form.role.as_str(), "banned" | "pending") {
        delete_sessions_for_user(&state.pool, &form.user_id)
            .await
            .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;
    }

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
    ctx.insert("success", "User role updated.");
    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_issue_reset(
    session:      Session,
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
    Form(form):   Form<ResetForm>,
) -> Result<Response, AppErrorResponse> {
    let base_url  = base_url_from_request(&headers);
    let reset_url = issue_password_reset(&state.pool, &form.user_id, &base_url)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
    ctx.insert("reset_url", &reset_url);
    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_create_client(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<CreateClientForm>,
) -> Result<Response, AppErrorResponse> {
    let id     = Uuid::new_v4().to_string();
    let secret = Uuid::new_v4().to_string();

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?
        .to_string();

    create_client(&state.pool, &id, &hash, form.name.trim())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    add_redirect_uri(&state.pool, &id, form.redirect_uri.trim())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
    ctx.insert("new_client_id",     &id);
    ctx.insert("new_client_secret", &secret);
    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_delete_client(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<DeleteClientForm>,
) -> Result<Response, AppErrorResponse> {
    delete_client(&state.pool, &form.client_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
    ctx.insert("success", "OAuth client deleted.");
    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_force_delete(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<ForceDeleteForm>,
) -> Result<Response, AppErrorResponse> {
    let secure = !crate::cfg::CONFIG.general.dev;

    let deleted_role_id = state.roles.id_for_name("deleted")
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("RBAC: deleted role not found in cache.".into())))?;

    delete_user(&state.pool, &form.user_id, &deleted_role_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    delete_sessions_for_user(&state.pool, &form.user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    revoke_all_tokens_for_user(&state.pool, &form.user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let _ = fs::remove_file(format!("{}/{}.gif", AVATAR_DIR, form.user_id)).await;

    let self_delete = session
        .get::<String>(crate::routes::auth::USER_SESSION_KEY)
        .map(|id| id == form.user_id)
        .unwrap_or(false);

    if self_delete {
        session.destroy().await;
        return Ok((clear_cookies(secure), Redirect::to("/auth/login")).into_response());
    }

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;
    ctx.insert("success", "User deleted.");
    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
