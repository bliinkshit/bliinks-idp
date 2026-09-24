# Bliinks Notifications Integration Guide

This guide explains how a Bliinks application can send notifications and display a user's shared Bliinks notification inbox.

Notifications are owned by the Hub. A notification created by one application can therefore appear in the Hub and in every integrated Bliinks application. Notifications expire 24 hours after creation.

---

## Before You Start

Ask a Hub administrator to configure your OAuth client with:

- A friendly application name, such as `Bliinks Forums`
- Your application's base URL, such as `https://forums.bliinks.net`
- Notifications enabled

The base URL must be the application origin. Do not include a page path such as `/forum` or `/chat`. The Hub joins this base URL to each notification's relative `target_path`.

Keep the OAuth client secret on your server. Never put it in browser JavaScript or return it to users.

---

## Notification Data

An application supplies three pieces of notification data:

| Field | Description |
|-------|-------------|
| `recipient_user_id` | The recipient's stable Bliinks user UUID. Store the `sub` value returned by `/oauth/userinfo`. |
| `text` | Plain notification text containing 1–500 characters. |
| `target_path` | A path inside your application, such as `/posts/123` or `/dms/salem`. It must begin with exactly one slash and may contain up to 2,048 characters. |

The Hub supplies the friendly application name and builds the final link by combining the OAuth client's configured base URL with `target_path`.

Treat notification text as untrusted user-facing data. Render it as text rather than inserting it as HTML.

---

## Sending a Notification

Send notifications from your application server:

```http
POST https://bliinks.net/api/v1/notifications
Authorization: Basic BASE64(CLIENT_ID:CLIENT_SECRET)
Content-Type: application/json
Idempotency-Key: forums:reply:550e8400-e29b-41d4-a716-446655440000

{
  "recipient_user_id": "USER_UUID_FROM_OAUTH_SUB",
  "text": "Salem replied to your post",
  "target_path": "/posts/42#reply-7"
}
```

`Idempotency-Key` is required and must contain 1–200 characters. Give each logical event a stable, unique key. Retrying the same event with the same key returns the existing notification instead of creating a duplicate. Keys are unique within your application, so a useful format is:

```text
app:event:local-event-id
```

A successful request returns `201 Created`:

```json
{
  "id": "NOTIFICATION_UUID",
  "recipient_user_id": "USER_UUID",
  "app_id": "OAUTH_CLIENT_UUID",
  "app_name": "Bliinks Forums",
  "text": "Salem replied to your post",
  "target_url": "https://forums.bliinks.net/posts/42#reply-7",
  "created_at": "2026-09-24T18:00:00Z",
  "expires_at": "2026-09-25T18:00:00Z"
}
```

### Node.js example

```js
async function sendBliinksNotification({
  recipientUserId,
  text,
  targetPath,
  idempotencyKey,
}) {
  const credentials = Buffer.from(
    `${process.env.BLIINKS_CLIENT_ID}:${process.env.BLIINKS_CLIENT_SECRET}`
  ).toString('base64');

  const response = await fetch(
    'https://bliinks.net/api/v1/notifications',
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${credentials}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
      },
      body: JSON.stringify({
        recipient_user_id: recipientUserId,
        text,
        target_path: targetPath,
      }),
    }
  );

  const body = await response.json();

  if (!response.ok) {
    throw new Error(
      `Bliinks notification failed (${response.status}): `
      + (body.error_description || body.error)
    );
  }

  return body;
}
```

Notification delivery should usually be best-effort. A temporary Hub failure should not prevent the primary action, such as saving a post or sending a direct message. Log failures so they can be diagnosed.

---

## Displaying the Shared Inbox

Add `notifications:read` to the scopes requested during OAuth login:

```text
openid profile notifications:read
```

Existing sessions and tokens do not gain newly requested scopes automatically. After adding the scope, users must complete the OAuth login flow again.

Inbox requests use the user's access token, not the application's client secret:

```http
Authorization: Bearer USER_ACCESS_TOKEN
```

Keep access and refresh tokens on your server. A good integration exposes same-origin routes from your application to the browser and has those routes proxy requests to the Hub. This avoids exposing tokens to frontend JavaScript.

Refresh expired access tokens using the normal OAuth refresh flow described in the [OAuth integration guide](oauth-integration-guide.md).

### List notifications

```http
GET https://bliinks.net/api/v1/notifications
Authorization: Bearer USER_ACCESS_TOKEN
```

The response is a JSON array containing up to 50 unexpired notifications, newest first:

```json
[
  {
    "id": "NOTIFICATION_UUID",
    "app_id": "OAUTH_CLIENT_UUID",
    "app_name": "Bliinks Forums",
    "text": "Salem replied to your post",
    "target_url": "https://forums.bliinks.net/posts/42#reply-7",
    "created_at": "2026-09-24T18:00:00Z",
    "read_at": null,
    "expires_at": "2026-09-25T18:00:00Z"
  }
]
```

Navigate to the returned `target_url` when the user opens a notification.

### Get the unread count

```http
GET https://bliinks.net/api/v1/notifications/unread-count
Authorization: Bearer USER_ACCESS_TOKEN
```

```json
{
  "unread_count": 3
}
```

### Mark one notification as read

```http
POST https://bliinks.net/api/v1/notifications/NOTIFICATION_UUID/read
Authorization: Bearer USER_ACCESS_TOKEN
```

The response is `204 No Content`.

### Mark every notification as read

```http
POST https://bliinks.net/api/v1/notifications/read-all
Authorization: Bearer USER_ACCESS_TOKEN
```

The response is `204 No Content`.

---

## User Preferences and Retention

Users control notifications from the Hub settings page. They can:

- Disable notifications from one application
- Disable all notifications without changing their per-application choices

The Hub enforces these preferences when an application sends a notification. Applications do not need to copy or cache the settings.

If a recipient does not exist, is unavailable, or has disabled the notification, the send endpoint returns `404 notification_not_accepted`. Treat this as a normal non-delivery result rather than repeatedly retrying it.

Notifications expire 24 hours after creation. List and unread-count responses exclude expired notifications.

---

## Errors

Errors use this shape:

```json
{
  "error": "invalid_client",
  "error_description": "Invalid client credentials."
}
```

Common sending errors:

| Status | Error | Meaning |
|--------|-------|---------|
| `400` | `invalid_recipient` | `recipient_user_id` is not a UUID. |
| `400` | `invalid_text` | Text is empty or longer than 500 characters. |
| `400` | `invalid_target_path` | The target is not a valid relative application path. |
| `400` | `invalid_idempotency_key` | The key is missing, empty, or longer than 200 characters. |
| `401` | `invalid_client` | Client credentials are missing or incorrect. |
| `403` | `notifications_disabled` | A Hub administrator has disabled sending for the application. |
| `403` | `app_not_configured` | The OAuth client has no notification base URL. |
| `404` | `notification_not_accepted` | The recipient is unavailable or has disabled delivery. |

Common inbox errors:

| Status | Error | Meaning |
|--------|-------|---------|
| `401` | `invalid_token` | The user access token is missing, invalid, or expired. |
| `403` | `insufficient_scope` | The token does not include `notifications:read`. |
| `404` | `notification_not_found` | The notification is missing, expired, or belongs to another user. |

---

## Integration Checklist

- Register the app's friendly name and base URL with a Hub administrator.
- Have the administrator enable notifications for the OAuth client.
- Store each user's OAuth `sub` as the stable Bliinks user ID.
- Send notifications from server-side code with Basic client authentication.
- Use a stable, unique `Idempotency-Key` for every logical event.
- Use relative paths beginning with `/`; never send a full URL as `target_path`.
- Request `notifications:read` if the app displays the shared inbox.
- Store and refresh user tokens server-side.
- Escape notification text when rendering it.
- Test administrator, global user, and per-app disable settings.
- Test both unread state and the final notification link.

