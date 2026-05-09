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

//internal
use crate::{
    db::{
        oauth_queries::{
            add_redirect_uri, create_client, delete_client, get_all_clients, revoke_all_tokens_for_user,
        },
        queries::{
            delete_sessions_for_user, get_all_users, issue_password_reset, set_user_admin,
            set_user_approved, delete_user,
        },
    },
    error::AppErrorResponse,
    render::render,
    AppState,
    session::{clear_cookies, Session},
    routes::avatar::AVATAR_DIR,
    helpers::get_user_ctx,
};

#[derive(Deserialize)]
pub struct ApproveForm {
    pub user_id:  String,
    pub approved: String,
}

#[derive(Deserialize)]
pub struct AdminForm {
    pub user_id: String,
    pub admin:   String,
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

    let mut unapproved = Vec::new();
    let mut approved   = Vec::new();
    let mut deleted    = Vec::new();

    for user in all_users {
        if user.deleted_at.is_some() {
            deleted.push(user);
        } else if user.approved {
            approved.push(user);
        } else {
            unapproved.push(user);
        }
    }

    let mut ctx = Context::new();
    ctx.insert("title",      "Admin Panel");
    ctx.insert("unapproved", &unapproved);
    ctx.insert("approved",   &approved);
    ctx.insert("deleted",    &deleted);
    ctx.insert("clients",    &clients);
    Ok(ctx)
}

pub async fn render_admin(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    let start = Instant::now();
    let mut ctx = build_ctx(&state).await?;

    get_user_ctx(&state.pool, &session, &mut ctx).await;

    render(&state.tera, "admin.html", &mut ctx, start)
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_approve(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<ApproveForm>,
) -> Result<Response, AppErrorResponse> {
    let approved = form.approved == "1";

    set_user_approved(&state.pool, &form.user_id, approved)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    if !approved {
        delete_sessions_for_user(&state.pool, &form.user_id)
            .await
            .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;
    }

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &session, &mut ctx).await;
    ctx.insert("success", "User approval status updated.");

    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_toggle_admin(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<AdminForm>,
) -> Result<Response, AppErrorResponse> {
    let admin = form.admin == "1";

    set_user_admin(&state.pool, &form.user_id, admin)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &session, &mut ctx).await;
    ctx.insert("success", "User admin status updated.");

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
    get_user_ctx(&state.pool, &session, &mut ctx).await;
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
        .map_err(|e| AppErrorResponse(Arc::clone(&state), crate::error::AppError::Internal(e.to_string())))?
        .to_string();

    create_client(&state.pool, &id, &hash, form.name.trim())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    add_redirect_uri(&state.pool, &id, form.redirect_uri.trim())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &session, &mut ctx).await;
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
    get_user_ctx(&state.pool, &session, &mut ctx).await;
    ctx.insert("success", "OAuth client deleted.");

    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct ForceDeleteForm {
    pub user_id: String,
}

pub async fn handle_force_delete(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<ForceDeleteForm>,
) -> Result<Response, AppErrorResponse> {
    let secure = !crate::cfg::CONFIG.general.dev;
 
    delete_user(&state.pool, &form.user_id)
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
        return Ok((
            clear_cookies(secure),
            Redirect::to("/auth/login"),
        ).into_response());
    }
 
    let mut ctx = build_ctx(&state).await?;
    get_user_ctx(&state.pool, &session, &mut ctx).await;
    ctx.insert("success", "User deleted.");
 
    render(&state.tera, "admin.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}
