// src/routes/auth.rs
use std::sync::Arc;
use std::time::Instant;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Form, Query, State},
    http::header,
    response::{Html, IntoResponse, Redirect, Response},
};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tera::Context;
use uuid::Uuid;

use crate::{
    db::queries::{
        create_password_reset, create_user, delete_sessions_for_user, get_password_reset,
        get_user_by_id, get_user_by_username, mark_password_reset_used, update_user_password,
    },
    error::{AppError, AppErrorResponse},
    render::render,
    routes::captcha::CAPTCHA_SESSION_KEY,
    session::{clear_cookies, Session},
    AppState,
};

pub const USER_SESSION_KEY: &str = "user_id";
const RESET_TOKEN_BYTES: usize   = 32;

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub captcha:  String,
    pub remember: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterForm {
    pub username:        String,
    pub password:        String,
    #[serde(rename = "password-repeat")]
    pub password_repeat: String,
    pub captcha:         String,
}

#[derive(Deserialize)]
pub struct ResetForm {
    pub token:           String,
    pub password:        String,
    #[serde(rename = "password-repeat")]
    pub password_repeat: String,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub reset: Option<String>,
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: Option<String>,
}

fn hash_input(input: &str) -> String {
    hex::encode(Sha256::digest(input.trim().as_bytes()))
}

fn verify_captcha(session: &Session, input: &str) -> bool {
    let Some(expected): Option<String> = session.get(CAPTCHA_SESSION_KEY) else {
        return false;
    };
    hash_input(&input.trim().to_uppercase()) == expected
}

macro_rules! render_err {
    ($state:expr, $template:expr, $ctx:expr, $msg:expr) => {{
        $ctx.insert("error", $msg);
        let html = render(&$state.tera, $template, &mut $ctx, Instant::now())
            .map_err(|e| AppErrorResponse(Arc::clone(&$state), e))?;
        return Ok(Html(html).into_response());
    }};
}

// to-do: deliver reset token hash
pub async fn issue_password_reset(
    pool:     &sqlx::SqlitePool,
    user_id:  &str,
    base_url: &str,
) -> Result<String, AppError> {
    let mut raw = [0u8; RESET_TOKEN_BYTES];
    OsRng.fill_bytes(&mut raw);
    let token      = hex::encode(raw);
    let token_hash = hash_input(&token);

    create_password_reset(pool, &token_hash, user_id).await?;

    Ok(format!("{}/auth/reset?token={}", base_url.trim_end_matches('/'), token))
}

pub async fn render_redirect() -> Redirect {
    Redirect::to("/auth/login")
}

pub async fn render_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> Result<Html<String>, AppErrorResponse> {
    let mut ctx = Context::new();
    if query.reset.as_deref() == Some("1") {
        ctx.insert("success", "Password reset! You can now log in with your new password.");
    }
    render(&state.tera, "login.html", &mut ctx, Instant::now())
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn render_register(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    render(&state.tera, "register.html", &mut Context::new(), Instant::now())
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn render_reset(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, AppErrorResponse> {
    let Some(token) = query.token else {
        return Ok(Redirect::to("/auth/login").into_response());
    };

    let token_hash = hash_input(&token);
    let valid = get_password_reset(&state.pool, &token_hash)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .is_some();

    let mut ctx = Context::new();
    if valid {
        ctx.insert("token", &token);
    } else {
        ctx.insert("error", "This reset link is invalid or has expired.");
    }

    render(&state.tera, "reset.html", &mut ctx, Instant::now())
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_login(
    mut session:  Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<LoginForm>,
) -> Result<Response, AppErrorResponse> {
    let secure   = !crate::cfg::CONFIG.general.dev;
    let remember = form.remember.as_deref() == Some("remember");
    let mut ctx  = Context::new();

    if !verify_captcha(&session, &form.captcha) {
        render_err!(state, "login.html", ctx, "Invalid CAPTCHA.");
    }

    let user = get_user_by_username(&state.pool, form.username.trim())
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let user = match user {
        Some(u) => u,
        None    => render_err!(state, "login.html", ctx, "Invalid username or password."),
    };

    let parsed = PasswordHash::new(&user.password)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        render_err!(state, "login.html", ctx, "Invalid username or password.");
    }

    if !user.approved {
        render_err!(state, "login.html", ctx, "Your account is pending admin approval.");
    }

    session.remember = remember;
    session.user_id  = Some(user.id.clone());
    session.regenerate().await;
    session.insert(USER_SESSION_KEY, &user.id);
    session.save().await;

    ctx.insert("success", "Logged in successfully!");
    let html = render(&state.tera, "login.html", &mut ctx, Instant::now())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut response = Html(html).into_response();
    let headers      = response.headers_mut();
    headers.append(header::SET_COOKIE, session.cookie_header(secure));
    if remember {
        headers.append(header::SET_COOKIE, session.remember_cookie_header(secure));
    }
    Ok(response)
}

pub async fn handle_register(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<RegisterForm>,
) -> Result<Response, AppErrorResponse> {
    let secure  = !crate::cfg::CONFIG.general.dev;
    let mut ctx = Context::new();

    if !verify_captcha(&session, &form.captcha) {
        render_err!(state, "register.html", ctx, "Invalid CAPTCHA.");
    }

    let username = form.username.trim();

    if username.is_empty() {
        render_err!(state, "register.html", ctx, "Username cannot be empty.");
    }
    if username.len() < 2 || username.len() > 32 {
        render_err!(state, "register.html", ctx, "Username must be 2-32 characters.");
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        render_err!(state, "register.html", ctx, "Username may only contain letters, numbers, and underscores.");
    }
    if form.password.len() < 6 {
        render_err!(state, "register.html", ctx, "Password must be at least 6 characters.");
    }
    if form.password != form.password_repeat {
        render_err!(state, "register.html", ctx, "Passwords do not match.");
    }
    if get_user_by_username(&state.pool, username)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .is_some()
    {
        render_err!(state, "register.html", ctx, "That username is already taken.");
    }

    let salt    = SaltString::generate(&mut OsRng);
    let hash    = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?
        .to_string();
    let id      = Uuid::new_v4().to_string();
    let created = chrono::Utc::now().to_rfc3339();

    create_user(&state.pool, &id, username, &hash, &created)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    ctx.insert(
        "success",
        "Account created! You'll need to wait for an admin to approve you before logging in.",
    );
    let html = render(&state.tera, "register.html", &mut ctx, Instant::now())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    Ok((
        [(header::SET_COOKIE, session.cookie_header(secure))],
        Html(html),
    ).into_response())
}

pub async fn handle_reset(
    mut session:  Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<ResetForm>,
) -> Result<Response, AppErrorResponse> {
    let secure     = !crate::cfg::CONFIG.general.dev;
    let token_hash = hash_input(&form.token);
    let mut ctx    = Context::new();
    ctx.insert("token", &form.token);

    let reset = get_password_reset(&state.pool, &token_hash)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let reset = match reset {
        Some(r) => r,
        None    => render_err!(state, "reset.html", ctx, "This reset link is invalid or has expired."),
    };

    if form.password.len() < 6 {
        render_err!(state, "reset.html", ctx, "Password must be at least 6 characters.");
    }
    if form.password != form.password_repeat {
        render_err!(state, "reset.html", ctx, "Passwords do not match.");
    }

    let user = get_user_by_id(&state.pool, &reset.user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| AppErrorResponse(Arc::clone(&state), AppError::Internal("User not found".into())))?;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?
        .to_string();

    mark_password_reset_used(&state.pool, &token_hash)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    update_user_password(&state.pool, &user.id, &hash)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    delete_sessions_for_user(&state.pool, &user.id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    session.destroy().await;

    Ok((
        clear_cookies(secure),
        Redirect::to("/auth/login?reset=1"),
    ).into_response())
}

pub async fn handle_logout(session: Session) -> Response {
    let secure = !crate::cfg::CONFIG.general.dev;
    session.destroy().await;
    (clear_cookies(secure), Redirect::to("/auth/login")).into_response()
}
