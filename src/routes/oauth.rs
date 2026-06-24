// src/routes/oauth.rs
use std::sync::Arc;
use std::time::Instant;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tera::Context;
use uuid::Uuid;

// internal
use crate::{
    db::{
        models::OAuthClient,
        oauth_queries::{
            consume_authorization_code, create_authorization_code, create_token, get_client,
            get_client_redirect_uris, get_token, revoke_token,
        },
        queries::get_user_by_id,
    },
    error::AppErrorResponse,
    oauth::{
        scopes,
        token::{self, ACCESS_TOKEN_TTL_MINUTES},
    },
    render::render,
    routes::auth::{USER_SESSION_KEY, OAUTH_NEXT_KEY},
    session::Session,
    AppState,
    helpers::get_user_ctx,
};

fn oauth_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error":             error,
            "error_description": description,
        })),
    )
        .into_response()
}

fn redirect_with_error(redirect_uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut url = format!("{}?error={}", redirect_uri, error);
    if let Some(s) = state {
        url.push_str(&format!("&state={}", s));
    }
    Redirect::to(&url).into_response()
}

fn extract_client_credentials(
    headers:     &HeaderMap,
    form_id:     Option<&str>,
    form_secret: Option<&str>,
) -> Option<(String, String)> {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(s) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = s.split_once(':') {
                        return Some((id.to_string(), secret.to_string()));
                    }
                }
            }
        }
    }

    match (form_id, form_secret) {
        (Some(id), Some(secret)) => Some((id.to_string(), secret.to_string())),
        _                        => None,
    }
}

async fn verify_client(
    pool:          &sqlx::PgPool,
    client_id_str: &str,
    client_secret: &str,
) -> Result<OAuthClient, Response> {
    let client_id = match client_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Err(oauth_error("invalid_client", "Unknown client.")),
    };

    let client = match get_client(pool, client_id).await {
        Ok(Some(c)) => c,
        _           => return Err(oauth_error("invalid_client", "Unknown client.")),
    };

    let parsed = match PasswordHash::new(&client.secret_hash) {
        Ok(h)  => h,
        Err(_) => return Err(oauth_error("invalid_client", "Invalid client.")),
    };

    if Argon2::default()
        .verify_password(client_secret.as_bytes(), &parsed)
        .is_err()
    {
        return Err(oauth_error("invalid_client", "Invalid client secret."));
    }

    Ok(client)
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub client_id:     String,
    pub redirect_uri:  String,
    pub response_type: String,
    pub scope:         Option<String>,
    pub state:         Option<String>,
}

pub async fn render_authorize(
    mut session:  Session,
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    if session.get::<String>(USER_SESSION_KEY).is_none() {
        let mut next = format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&response_type={}",
            urlencoding::encode(&query.client_id),
            urlencoding::encode(&query.redirect_uri),
            urlencoding::encode(&query.response_type),
        );
        if let Some(scope) = &query.scope {
            next.push_str(&format!("&scope={}", urlencoding::encode(scope)));
        }
        if let Some(state_val) = &query.state {
            next.push_str(&format!("&state={}", urlencoding::encode(state_val)));
        }
        session.insert(OAUTH_NEXT_KEY, &next);
        session.save().await;
        return Ok(Redirect::to("/auth/login").into_response());
    }

    if query.response_type != "code" {
        return Ok(oauth_error("unsupported_response_type", "Only 'code' is supported."));
    }

    let client_id = match query.client_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(oauth_error("invalid_client", "Unknown client.")),
    };

    let client = get_client(&state.pool, client_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let client = match client {
        Some(c) => c,
        None    => return Ok(oauth_error("invalid_client", "Unknown client.")),
    };

    let allowed_uris = get_client_redirect_uris(&state.pool, client_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    if !allowed_uris.contains(&query.redirect_uri) {
        return Ok(oauth_error("invalid_request", "redirect_uri not registered for this client."));
    }

    let scopes = scopes::parse(query.scope.as_deref().unwrap_or("openid"));

    if !scopes.contains(scopes::OPENID) {
        return Ok(redirect_with_error(
            &query.redirect_uri,
            "invalid_scope",
            query.state.as_deref(),
        ));
    }

    let mut ctx = Context::new();
    ctx.insert("title",        "Authorize Application");
    ctx.insert("client_name",  &client.name);
    ctx.insert("client_id",    &query.client_id);
    ctx.insert("redirect_uri", &query.redirect_uri);
    ctx.insert("scope",        &scopes::serialize(&scopes));
    ctx.insert("state",        query.state.as_deref().unwrap_or(""));
    ctx.insert("has_profile",  &scopes.contains(scopes::PROFILE));

    get_user_ctx(&state.pool, &state.roles, &session, &mut ctx).await;

    render(&state.tera, "auth/authorize.html", &mut ctx, start)
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct AuthorizeForm {
    pub client_id:    String,
    pub redirect_uri: String,
    pub scope:        String,
    pub state:        Option<String>,
    pub action:       String,
}

pub async fn handle_authorize(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<AuthorizeForm>,
) -> Result<Response, AppErrorResponse> {
    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    if form.action != "approve" {
        return Ok(redirect_with_error(
            &form.redirect_uri,
            "access_denied",
            form.state.as_deref(),
        ));
    }

    let client_id = match form.client_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(oauth_error("invalid_client", "Unknown client.")),
    };

    let allowed_uris = get_client_redirect_uris(&state.pool, client_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    if !allowed_uris.contains(&form.redirect_uri) {
        return Ok(oauth_error("invalid_request", "redirect_uri not registered for this client."));
    }

    let scopes = scopes::parse(&form.scope);

    if !scopes.contains(scopes::OPENID) {
        return Ok(redirect_with_error(
            &form.redirect_uri,
            "invalid_scope",
            form.state.as_deref(),
        ));
    }

    let (code, _) = token::generate();

    create_authorization_code(
        &state.pool,
        &code,
        client_id,
        user_id,
        &form.redirect_uri,
        &scopes::serialize(&scopes),
    )
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut url = format!("{}?code={}", form.redirect_uri, code);
    if let Some(s) = &form.state {
        url.push_str(&format!("&state={}", s));
    }

    Ok(Redirect::to(&url).into_response())
}

#[derive(Deserialize)]
pub struct TokenForm {
    pub grant_type:    String,
    pub code:          Option<String>,
    pub redirect_uri:  Option<String>,
    pub client_id:     Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token:  String,
    pub token_type:    &'static str,
    pub expires_in:    i64,
    pub refresh_token: String,
    pub scope:         String,
}

pub async fn handle_token(
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
    Form(form):   Form<TokenForm>,
) -> Response {
    let Some((client_id, client_secret)) = extract_client_credentials(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    ) else {
        return oauth_error("invalid_client", "Missing client credentials.");
    };

    let client = match verify_client(&state.pool, &client_id, &client_secret).await {
        Ok(c)    => c,
        Err(res) => return res,
    };

    match form.grant_type.as_str() {
        "authorization_code" => handle_token_auth_code(&state, client.id, &form).await,
        "refresh_token"      => handle_token_refresh(&state, client.id, &form).await,
        _                    => oauth_error(
            "unsupported_grant_type",
            "Supported: authorization_code, refresh_token.",
        ),
    }
}

async fn handle_token_auth_code(
    state:     &Arc<AppState>,
    client_id: Uuid,
    form:      &TokenForm,
) -> Response {
    let (Some(code), Some(redirect_uri)) = (&form.code, &form.redirect_uri) else {
        return oauth_error("invalid_request", "Missing code or redirect_uri.");
    };

    let auth_code = match consume_authorization_code(&state.pool, code).await {
        Ok(Some(c)) => c,
        _           => return oauth_error("invalid_grant", "Invalid or expired code."),
    };

    if auth_code.client_id != client_id || &auth_code.redirect_uri != redirect_uri {
        return oauth_error("invalid_grant", "Code was not issued for this client or redirect_uri.");
    }

    issue_token_pair(state, client_id, auth_code.user_id, &auth_code.scopes).await
}

async fn handle_token_refresh(
    state:     &Arc<AppState>,
    client_id: Uuid,
    form:      &TokenForm,
) -> Response {
    let Some(refresh_token) = &form.refresh_token else {
        return oauth_error("invalid_request", "Missing refresh_token.");
    };

    let stored = match get_token(&state.pool, &token::hash(refresh_token), "refresh").await {
        Ok(Some(t)) => t,
        _           => return oauth_error("invalid_grant", "Invalid or expired refresh token."),
    };

    if stored.client_id != client_id {
        return oauth_error("invalid_grant", "Token was not issued for this client.");
    }

    if revoke_token(&state.pool, &stored.token_hash).await.is_err() {
        return oauth_error("server_error", "Failed to rotate refresh token.");
    }

    issue_token_pair(state, client_id, stored.user_id, &stored.scopes).await
}

async fn issue_token_pair(
    state:     &Arc<AppState>,
    client_id: Uuid,
    user_id:   Uuid,
    scopes:    &str,
) -> Response {
    let (access_token,  access_hash)  = token::generate();
    let (refresh_token, refresh_hash) = token::generate();

    let access_expiry  = token::access_token_expiry();
    let refresh_expiry = token::refresh_token_expiry();

    let a = create_token(&state.pool, &access_hash,  client_id, user_id, "access",  scopes, access_expiry).await;
    let r = create_token(&state.pool, &refresh_hash, client_id, user_id, "refresh", scopes, refresh_expiry).await;

    if a.is_err() || r.is_err() {
        return oauth_error("server_error", "Failed to issue tokens.");
    }

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_MINUTES * 60,
        refresh_token,
        scope: scopes.to_string(),
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct RevokeForm {
    pub token:         String,
    pub client_id:     Option<String>,
    pub client_secret: Option<String>,
}

pub async fn handle_revoke(
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
    Form(form):   Form<RevokeForm>,
) -> Response {
    let Some((client_id, client_secret)) = extract_client_credentials(
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    ) else {
        return oauth_error("invalid_client", "Missing client credentials.");
    };

    if let Err(res) = verify_client(&state.pool, &client_id, &client_secret).await {
        return res;
    }

    let _ = revoke_token(&state.pool, &token::hash(&form.token)).await;

    StatusCode::OK.into_response()
}

#[derive(Serialize)]
pub struct UserinfoResponse {
    pub sub:          String,
    pub username:     String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color:        Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture:      Option<String>,
    pub date_created: String,
    pub role:         String,
}

pub async fn handle_userinfo(
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
) -> Response {
    let token_str = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None    => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "invalid_token",
        }))).into_response(),
    };

    let stored = match get_token(&state.pool, &token::hash(&token_str), "access").await {
        Ok(Some(t)) => t,
        _           => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "invalid_token",
        }))).into_response(),
    };

    let user = match get_user_by_id(&state.pool, stored.user_id).await {
        Ok(Some(u)) => u,
        _           => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "invalid_token",
        }))).into_response(),
    };

    if user.is_deleted() {
        return (StatusCode::GONE, Json(serde_json::json!({
            "error":             "user_deleted",
            "error_description": "This account has been deleted.",
        }))).into_response();
    }

    let has_profile = scopes::contains(&stored.scopes, scopes::PROFILE);

    let picture = if has_profile && user.avatar_updated_at.is_some() {
        let host   = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("localhost");
        let scheme = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("http");
        let ts     = user.avatar_updated_at.map(|t| t.timestamp_millis().to_string()).unwrap_or_default();
        Some(format!("{}://{}/avatars/{}?v={}", scheme, host, user.id, ts))
    } else {
        None
    };

    let role_name = state.roles.name_for_id(&user.role).unwrap_or_default();

    Json(UserinfoResponse {
        sub:          user.id.to_string(),
        username:     user.username,
        display_name: if has_profile { user.display_name } else { None },
        color:        if has_profile { user.color } else { None },
        picture,
        date_created: user.date_created.to_rfc3339(),
        role:         role_name,
    })
    .into_response()
}
