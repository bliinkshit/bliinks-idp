use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tera::Context;
use uuid::Uuid;

use crate::{
    db::{
    models::NotificationWithApp,
    notification_queries::{
        count_unread as count_unread_notifications,
        create_notification as insert_notification,
        list_notifications as load_notifications,
        mark_all_read as mark_all_notifications_read,
        mark_read as mark_notification_read,
        get_notification_for_user,
    },
    oauth_queries::get_token,
    queries::get_user_by_id,
},
   oauth::{
    client_auth::{
        authenticate_client,
        extract_basic_credentials,
    },
    scopes,
    token,
},
    error::{AppError, AppErrorResponse},
    helpers::insert_user_ctx,
    render::render,
    routes::auth::USER_SESSION_KEY,
    session::Session,
AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateNotificationRequest {
    pub recipient_user_id: String,
    pub text: String,
    pub target_path: String,
}

#[derive(Debug, Serialize)]
pub struct CreateNotificationResponse {
    pub id:                String,
    pub recipient_user_id: String,
    pub app_id:            String,
    pub app_name:          String,
    pub text:              String,
    pub target_url:        String,
    pub created_at:        DateTime<Utc>,
    pub expires_at:        DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct NotificationResponse {
    pub id:         String,
    pub app_id:     String,
    pub app_name:   String,
    pub text:       String,
    pub target_url: String,
    pub created_at: DateTime<Utc>,
    pub read_at:    Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

impl From<NotificationWithApp> for NotificationResponse {
    fn from(notification: NotificationWithApp) -> Self {
        let target_url = format!(
            "{}{}",
            notification.base_url.trim_end_matches('/'),
            notification.target_path,
        );

        Self {
            id: notification.id.to_string(),
            app_id: notification.client_id.to_string(),
            app_name: notification.app_name,
            text: notification.text,
            target_url,
            created_at: notification.created_at,
            read_at: notification.read_at,
            expires_at: notification.expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    pub unread_count: i64,
}

pub async fn render_inbox(
    session: Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user = get_user_by_id(&state.pool, user_id)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
        .ok_or_else(|| {
            AppErrorResponse(
                Arc::clone(&state),
                AppError::Internal("User not found".into()),
            )
        })?;

    let notifications = load_notifications(
        &state.pool,
        user_id,
        50,
    )
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
    .into_iter()
    .map(NotificationResponse::from)
    .collect::<Vec<_>>();

    let unread_count = count_unread_notifications(
        &state.pool,
        user_id,
    )
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    let mut ctx = Context::new();
    ctx.insert("title", "Notifications");
    ctx.insert("page", "notifications");
    ctx.insert("notifications", &notifications);
    ctx.insert("unread_count", &unread_count);
    insert_user_ctx(&mut ctx, &user, &state.roles);

    render(
        &state.tera,
        "notifications.html",
        &mut ctx,
        start,
    )
    .map(|html| Html(html).into_response())
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn open_notification(
    session: Session,
    State(state): State<Arc<AppState>>,
    Path(notification_id): Path<String>,
) -> Result<Response, AppErrorResponse> {
    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let notification_id = notification_id
        .parse::<Uuid>()
        .map_err(|_| {
            AppErrorResponse(
                Arc::clone(&state),
                AppError::BadRequest(
                    "Invalid notification ID.".into(),
                ),
            )
        })?;

    let notification = get_notification_for_user(
        &state.pool,
        notification_id,
        user_id,
    )
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?
    .ok_or_else(|| {
        AppErrorResponse(
            Arc::clone(&state),
            AppError::BadRequest(
                "That notification does not exist or has expired.".into(),
            ),
        )
    })?;

    let target_url = NotificationResponse::from(notification).target_url;

    mark_notification_read(
        &state.pool,
        notification_id,
        user_id,
    )
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    Ok(Redirect::to(&target_url).into_response())
}

pub async fn handle_inbox_mark_all_read(
    session: Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    let user_id_str: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Ok(Redirect::to("/auth/login").into_response()),
    };

    mark_all_notifications_read(
        &state.pool,
        user_id,
    )
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    Ok(Redirect::to("/notifications").into_response())
}

fn api_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}
async fn authenticated_notification_user(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<Uuid, Response> {
    let Some(access_token) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "A bearer access token is required.",
        ));
    };

    let stored_token = match get_token(
        &state.pool,
        &token::hash(access_token),
        "access",
    )
    .await
    {
        Ok(Some(stored_token)) => stored_token,
        Ok(None) => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The access token is invalid or expired.",
            ));
        }
        Err(_) => {
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Token validation failed.",
            ));
        }
    };

    if !scopes::contains(
        &stored_token.scopes,
        scopes::NOTIFICATIONS_READ,
    ) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "The access token requires notifications:read.",
        ));
    }

    let user = match get_user_by_id(
        &state.pool,
        stored_token.user_id,
    )
    .await
    {
        Ok(Some(user)) if !user.is_deleted() => user,
        _ => {
            return Err(api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The token user is unavailable.",
            ));
        }
    };

    Ok(user.id)
}

pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let user_id = match authenticated_notification_user(
        &state,
        &headers,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let notifications = match load_notifications(
        &state.pool,
        user_id,
        50,
    )
    .await
    {
        Ok(notifications) => notifications,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The notification inbox could not be loaded.",
            );
        }
    };

    let response: Vec<NotificationResponse> = notifications
        .into_iter()
        .map(NotificationResponse::from)
        .collect();

    Json(response).into_response()
}

pub async fn unread_count(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let user_id = match authenticated_notification_user(
        &state,
        &headers,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let unread_count = match count_unread_notifications(
        &state.pool,
        user_id,
    )
    .await
    {
        Ok(count) => count,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The unread notification count could not be loaded.",
            );
        }
    };

    Json(UnreadCountResponse { unread_count }).into_response()
}

pub async fn mark_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(notification_id): Path<String>,
) -> Response {
    let user_id = match authenticated_notification_user(
        &state,
        &headers,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let notification_id = match notification_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_notification_id",
                "The notification ID must be a UUID.",
            );
        }
    };

    match mark_notification_read(
        &state.pool,
        notification_id,
        user_id,
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => api_error(
            StatusCode::NOT_FOUND,
            "notification_not_found",
            "The notification does not exist or has expired.",
        ),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "The notification could not be marked as read.",
        ),
    }
}

pub async fn mark_all_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let user_id = match authenticated_notification_user(
        &state,
        &headers,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    match mark_all_notifications_read(
        &state.pool,
        user_id,
    )
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "The notifications could not be marked as read.",
        ),
    }
}

pub async fn create_notification(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateNotificationRequest>,
) -> Response {
    let Some((client_id, client_secret)) =
        extract_basic_credentials(&headers)
    else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Missing or invalid HTTP Basic credentials.",
        );
    };

    let client = match authenticate_client(
        &state.pool,
        &client_id,
        &client_secret,
    )
    .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Invalid client credentials.",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Client authentication failed.",
            );
        }
    };

    if !client.notifications_enabled {
        return api_error(
            StatusCode::FORBIDDEN,
            "notifications_disabled",
            "This application cannot send notifications.",
        );
    }

    let Some(base_url) = client.base_url.as_deref() else {
        return api_error(
            StatusCode::FORBIDDEN,
            "app_not_configured",
            "This application has no notification base URL.",
        );
    };

    let recipient_id = match payload.recipient_user_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_recipient",
                "recipient_user_id must be a UUID.",
            );
        }
    };

    let text = payload.text.trim();
    if text.is_empty() || text.chars().count() > 500 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_text",
            "text must contain between 1 and 500 characters.",
        );
    }

    let target_path = payload.target_path.trim();
    if !target_path.starts_with('/')
        || target_path.starts_with("//")
        || target_path.chars().count() > 2048
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_target_path",
            "target_path must be a relative path beginning with one slash.",
        );
    }

    let Some(idempotency_key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.chars().count() <= 200)
    else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "Idempotency-Key must contain between 1 and 200 characters.",
        );
    };

    let notification = match insert_notification(
        &state.pool,
        recipient_id,
        client.id,
        text,
        target_path,
        idempotency_key,
    )
    .await
    {
        Ok(Some(notification)) => notification,
              Ok(None) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "notification_not_accepted",
                "The recipient is unavailable or has disabled these notifications.",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "The notification could not be stored.",
            );
        }
    };

    let target_url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        notification.target_path,
    );

    (
        StatusCode::CREATED,
        Json(CreateNotificationResponse {
            id: notification.id.to_string(),
            recipient_user_id: notification.recipient_id.to_string(),
            app_id: client.id.to_string(),
            app_name: client.name,
            text: notification.text,
            target_url,
            created_at: notification.created_at,
            expires_at: notification.expires_at,
        }),
    )
        .into_response()
}