// src/routes/auth.rs
use std::sync::Arc;
use std::time::Instant;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Form, State},
    http::header,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tera::Context;
use uuid::Uuid;

use crate::{
    db::queries::{create_user, get_user_by_username},
    error::{AppError, AppErrorResponse},
    render::render,
    routes::captcha::CAPTCHA_SESSION_KEY,
    session::{clear_cookies, Session},
    AppState,
};

pub const USER_SESSION_KEY: &str = "user_id";

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

pub async fn render_redirect() -> Redirect {
    Redirect::to("/auth/login")
}

pub async fn render_login(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    let start   = Instant::now();
    let mut ctx = Context::new();
    render(&state.tera, "login.html", &mut ctx, start)
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn render_register(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppErrorResponse> {
    let start   = Instant::now();
    let mut ctx = Context::new();
    render(&state.tera, "register.html", &mut ctx, start)
        .map(Html)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_login(
    mut session:  Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<LoginForm>,
) -> Result<Response, AppErrorResponse> {
    let secure   = !crate::cfg::CONFIG.general.dev;
    let remember = form.remember.as_deref() == Some("remember");

    macro_rules! render_err {
        ($msg:expr, $ctx:expr) => {{
            $ctx.insert("error", $msg);
            let html = render(&state.tera, "login.html", &mut $ctx, Instant::now())
                .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;
            return Ok((
                [(header::SET_COOKIE, session.cookie_header(secure))],
                Html(html),
            ).into_response());
        }};
    }

    let mut ctx = Context::new();

    if !verify_captcha(&session, &form.captcha) {
        render_err!("Invalid CAPTCHA.", ctx);
    }

    let username = form.username.trim();
    let user = get_user_by_username(&state.pool, username)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let user = match user {
        Some(u) => u,
        None    => render_err!("Invalid username or password.", ctx),
    };

    let parsed = PasswordHash::new(&user.password)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?;

    if Argon2::default().verify_password(form.password.as_bytes(), &parsed).is_err() {
        render_err!("Invalid username or password.", ctx);
    }

    if !user.approved {
        render_err!("Your account is pending admin approval.", ctx);
    }

    session.remember = remember;
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
    let secure = !crate::cfg::CONFIG.general.dev;

    macro_rules! render_err {
        ($msg:expr, $ctx:expr) => {{
            $ctx.insert("error", $msg);
            let html = render(&state.tera, "register.html", &mut $ctx, Instant::now())
                .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;
            return Ok((
                [(header::SET_COOKIE, session.cookie_header(secure))],
                Html(html),
            ).into_response());
        }};
    }

    let mut ctx = Context::new();

    if !verify_captcha(&session, &form.captcha) {
        render_err!("Invalid CAPTCHA.", ctx);
    }

    let username = form.username.trim();

    if username.is_empty() { render_err!("Username cannot be empty.", ctx); }

    if username.len() > 32 || username.len() < 2 { render_err!("Username must be 2-32 characters.", ctx); }
    
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        render_err!("Username may only contain letters, numbers, and underscores.", ctx);
    }

    if form.password.len() < 6 { render_err!("Password must be at least 6 characters.", ctx); }

    if form.password != form.password_repeat { render_err!("Passwords do not match.", ctx); }

    if get_user_by_username(&state.pool, username)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .is_some()
    {
        render_err!("That username is already taken.", ctx);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?
        .to_string();

    let id = Uuid::new_v4().to_string();
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

pub async fn handle_logout(
    session:      Session,
) -> Response {
    let secure = !crate::cfg::CONFIG.general.dev;
    session.destroy().await;
    let cookies = clear_cookies(secure);
    (cookies, Redirect::to("/auth/login")).into_response()
}

fn verify_captcha(session: &Session, input: &str) -> bool {
    let Some(expected): Option<String> = session.get(CAPTCHA_SESSION_KEY) else {
        return false;
    };
    let input_hash = hex::encode(Sha256::digest(input.trim().to_uppercase().as_bytes()));
    input_hash == expected
}
