use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;
use super::models::{
    Notification,
    NotificationPreferenceWithApp,
    NotificationWithApp,
};

pub async fn create_notification(
    pool: &PgPool,
    recipient_id: Uuid,
    client_id: Uuid,
    text: &str,
    target_path: &str,
    idempotency_key: &str,
) -> Result<Option<Notification>, AppError> {
       sqlx::query_as::<_, Notification>(
        "INSERT INTO notifications
            (id, recipient_id, client_id, text, target_path, idempotency_key)
         SELECT $1, $2, $3, $4, $5, $6
         FROM users u
         INNER JOIN oauth_clients c
           ON c.id = $3
         LEFT JOIN notification_user_settings s
           ON s.user_id = u.id
         LEFT JOIN notification_preferences p
           ON p.user_id = u.id
          AND p.client_id = c.id
         WHERE u.id = $2
           AND u.deleted_at IS NULL
           AND c.notifications_enabled = TRUE
           AND COALESCE(s.notifications_enabled, TRUE) = TRUE
           AND COALESCE(p.enabled, TRUE) = TRUE
         ON CONFLICT (client_id, idempotency_key)
         DO UPDATE SET id = notifications.id
         RETURNING
             id,
             recipient_id,
             client_id,
             text,
             target_path,
             idempotency_key,
             created_at,
             read_at,
             expires_at",
    )
    .bind(Uuid::new_v4())
    .bind(recipient_id)
    .bind(client_id)
    .bind(text)
    .bind(target_path)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn list_notifications(
    pool: &PgPool,
    recipient_id: Uuid,
    limit: i64,
) -> Result<Vec<NotificationWithApp>, AppError> {
    sqlx::query_as::<_, NotificationWithApp>(
        "SELECT
             n.id,
             n.client_id,
             c.name AS app_name,
             c.base_url AS base_url,
             n.text,
             n.target_path,
             n.created_at,
             n.read_at,
             n.expires_at
         FROM notifications n
         INNER JOIN oauth_clients c ON c.id = n.client_id
         WHERE n.recipient_id = $1
           AND n.expires_at > NOW()
           AND c.base_url IS NOT NULL
         ORDER BY n.created_at DESC, n.id DESC
         LIMIT $2",
    )
    .bind(recipient_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn get_notification_for_user(
    pool: &PgPool,
    notification_id: Uuid,
    recipient_id: Uuid,
) -> Result<Option<NotificationWithApp>, AppError> {
    sqlx::query_as::<_, NotificationWithApp>(
        "SELECT
            n.id,
            n.client_id,
            c.name AS app_name,
            c.base_url AS base_url,
            n.text,
            n.target_path,
            n.created_at,
            n.read_at,
            n.expires_at
         FROM notifications n
         INNER JOIN oauth_clients c
           ON c.id = n.client_id
         WHERE n.id = $1
           AND n.recipient_id = $2
           AND n.expires_at > NOW()
           AND c.base_url IS NOT NULL",
    )
    .bind(notification_id)
    .bind(recipient_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn count_unread(
    pool: &PgPool,
    recipient_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM notifications
         WHERE recipient_id = $1
           AND read_at IS NULL
           AND expires_at > NOW()",
    )
    .bind(recipient_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn mark_read(
    pool: &PgPool,
    notification_id: Uuid,
    recipient_id: Uuid,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE notifications
         SET read_at = COALESCE(read_at, NOW())
         WHERE id = $1
           AND recipient_id = $2
           AND expires_at > NOW()",
    )
    .bind(notification_id)
    .bind(recipient_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(result.rows_affected() == 1)
}

pub async fn mark_all_read(
    pool: &PgPool,
    recipient_id: Uuid,
) -> Result<u64, AppError> {
    let result = sqlx::query(
        "UPDATE notifications
         SET read_at = NOW()
         WHERE recipient_id = $1
           AND read_at IS NULL
           AND expires_at > NOW()",
    )
    .bind(recipient_id)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(result.rows_affected())
}

pub async fn get_user_notifications_enabled(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE(
            (
                SELECT notifications_enabled
                FROM notification_user_settings
                WHERE user_id = $1
            ),
            TRUE
        )",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn list_notification_preferences(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<NotificationPreferenceWithApp>, AppError> {
    sqlx::query_as::<_, NotificationPreferenceWithApp>(
        "SELECT
            c.id AS client_id,
            c.name AS app_name,
            COALESCE(p.enabled, TRUE) AS enabled
         FROM oauth_clients c
         LEFT JOIN notification_preferences p
           ON p.client_id = c.id
          AND p.user_id = $1
         WHERE c.notifications_enabled = TRUE
         ORDER BY c.name ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn set_user_notifications_enabled(
    pool: &PgPool,
    user_id: Uuid,
    enabled: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO notification_user_settings
            (user_id, notifications_enabled, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET
            notifications_enabled = EXCLUDED.notifications_enabled,
            updated_at = NOW()",
    )
    .bind(user_id)
    .bind(enabled)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(())
}

pub async fn set_app_notifications_enabled(
    pool: &PgPool,
    user_id: Uuid,
    client_id: Uuid,
    enabled: bool,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "INSERT INTO notification_preferences
            (user_id, client_id, enabled, updated_at)
         SELECT $1, c.id, $3, NOW()
         FROM oauth_clients c
         WHERE c.id = $2
           AND c.notifications_enabled = TRUE
         ON CONFLICT (user_id, client_id)
         DO UPDATE SET
            enabled = EXCLUDED.enabled,
            updated_at = NOW()",
    )
    .bind(user_id)
    .bind(client_id)
    .bind(enabled)
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(result.rows_affected() == 1)
}

pub async fn delete_expired(pool: &PgPool) {
    let _ = sqlx::query(
        "DELETE FROM notifications WHERE expires_at <= NOW()",
    )
    .execute(pool)
    .await;
}