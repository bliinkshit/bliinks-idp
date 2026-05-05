# Bliinks OAuth Integration Guide

This guide covers everything you need to add Bliinks login to your app. The system follows standard OAuth 2.0 with Authorization Code flow. If you've used GitHub or Google login before, this will feel familiar.

---

## Before You Start

You'll need an admin to register your app. Give them:

- Your app's name
- One or more redirect URIs (the URLs Bliinks will send users back to after login)

They'll give you back a **client ID** and **client secret**. Keep the secret out of version control and never expose it in frontend code.

---

## Scopes

Request only what you need:

| Scope | What you get |
|-------|-------------|
| `openid` | User's ID (`sub`), username, and account creation date. Required. |
| `profile` | Display name, colour preference, and avatar (if set). |

---

## The Login Flow

### Step 1: Redirect the user to Bliinks

Send the user to:

```
GET https://bliinks.net/oauth/authorize
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=https://yourapp.com/callback
  &response_type=code
  &scope=openid%20profile
  &state=RANDOM_STRING
```

The `state` parameter should be a random string you generate and store in the user's session. You'll verify it in step 3 to prevent CSRF attacks.

### Step 2: User approves

Bliinks shows the user a consent screen listing what your app is requesting. If they approve, they're redirected back to your `redirect_uri`:

```
https://yourapp.com/callback?code=AUTHORIZATION_CODE&state=YOUR_STATE
```

If they deny, you'll get:

```
https://yourapp.com/callback?error=access_denied
```

### Step 3: Exchange the code for tokens

Verify that the `state` matches what you stored. Then make a server-side POST request:

```http
POST https://bliinks.net/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTHORIZATION_CODE
&redirect_uri=https://yourapp.com/callback
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

You'll receive:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "...",
  "scope": "openid profile"
}
```

Store both tokens. The access token is short-lived (15 minutes). The refresh token lasts 30 days and lets you get new access tokens without asking the user to log in again.

### Step 4: Fetch the user's profile

```http
GET https://bliinks.net/oauth/userinfo
Authorization: Bearer ACCESS_TOKEN
```

Response for `openid` scope:

```json
{
  "sub": "user-uuid",
  "username": "salem",
  "date_created": "2024-01-15T10:30:00Z"
}
```

Response for `openid profile` scope:

```json
{
  "sub": "user-uuid",
  "username": "salem",
  "date_created": "2024-01-15T10:30:00Z",
  "display_name": "Salem",
  "color": "#ff6b6b",
  "picture": "https://bliinks.net/avatars/user-uuid?v=2024-01-15T10:30:00Z"
}
```

`picture` is omitted if the user has not set an avatar.

Use `sub` as the user's unique identifier in your own database. Do not use `username` as a key since it may change in the future.

---

## Refreshing Access Tokens

When the access token expires, use the refresh token to get a new pair:

```http
POST https://bliinks.net/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=YOUR_REFRESH_TOKEN
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

You'll receive a fresh access token and a fresh refresh token. Replace both since the old refresh token is immediately invalidated on use.

---

## Revoking Tokens

When a user logs out of your app, revoke their tokens:

```http
POST https://bliinks.net/oauth/token/revoke
Content-Type: application/x-www-form-urlencoded

token=TOKEN_TO_REVOKE
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

This works for both access and refresh tokens. Always do this on logout, don't just delete the token from your own storage.

---

## Error Responses

All errors follow the same shape:

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired code."
}
```

Common errors:

| Error | Meaning |
|-------|---------|
| `invalid_client` | Wrong client ID or secret |
| `invalid_grant` | Code or refresh token is expired, already used, or wrong |
| `invalid_scope` | You must include `openid` |
| `access_denied` | User clicked deny |
| `unsupported_response_type` | Only `code` is supported |

---

## Quick Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/oauth/authorize` | GET | Start login flow |
| `/oauth/authorize` | POST | User approves/denies |
| `/oauth/token` | POST | Exchange code or refresh tokens |
| `/oauth/token/revoke` | POST | Revoke a token |
| `/oauth/userinfo` | GET | Fetch user profile |

---

## Example: Node.js (Express)

```js
const crypto = require('crypto');

// Start login
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id:     process.env.CLIENT_ID,
    redirect_uri:  'https://yourapp.com/callback',
    response_type: 'code',
    scope:         'openid profile',
    state,
  });

  res.redirect(`https://bliinks.net/oauth/authorize?${params}`);
});

// Handle callback
app.get('/callback', async (req, res) => {
  if (req.query.state !== req.session.oauthState) {
    return res.status(400).send('State mismatch');
  }
  if (req.query.error) {
    return res.status(400).send('Access denied');
  }

  const tokenRes = await fetch('https://bliinks.net/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'authorization_code',
      code:          req.query.code,
      redirect_uri:  'https://yourapp.com/callback',
      client_id:     process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
    }),
  });

  const { access_token, refresh_token } = await tokenRes.json();

  const userRes  = await fetch('https://bliinks.net/oauth/userinfo', {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  const user = await userRes.json();

  req.session.user         = user;
  req.session.accessToken  = access_token;
  req.session.refreshToken = refresh_token;

  res.redirect('/');
});
```

---

## Example: Go (Fiber)

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

var (
	store        = session.New()
	baseURL      = "https://bliinks.net"
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	redirectURI  = "https://yourapp.com/callback"
)

func main() {
	app := fiber.New()

	app.Get("/login", handleLogin)
	app.Get("/callback", handleCallback)

	app.Listen(":3000")
}

func handleLogin(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return err
	}

	state := fmt.Sprintf("%x", make([]byte, 16))
	sess.Set("oauth_state", state)
	sess.Save()

	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {state},
	}

	return c.Redirect(baseURL + "/oauth/authorize?" + params.Encode())
}

func handleCallback(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return err
	}

	if c.Query("state") != sess.Get("oauth_state") {
		return c.Status(400).SendString("State mismatch")
	}
	if c.Query("error") != "" {
		return c.Status(400).SendString("Access denied")
	}

	tokenRes, err := http.PostForm(baseURL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {c.Query("code")},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return err
	}
	defer tokenRes.Body.Close()

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(tokenRes.Body).Decode(&tokens)

	req, _ := http.NewRequest("GET", baseURL+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	userRes, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer userRes.Body.Close()

	body, _ := io.ReadAll(userRes.Body)

	sess.Set("user", string(body))
	sess.Set("access_token", tokens.AccessToken)
	sess.Set("refresh_token", tokens.RefreshToken)
	sess.Save()

	return c.Redirect("/")
}
```

---

## Example: Python (Flask)

```python
import os, secrets, requests
from flask import Flask, redirect, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ['FLASK_SECRET']

BASE_URL   = 'https://bliinks.net'
CLIENT_ID  = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
REDIRECT_URI  = 'https://yourapp.com/callback'

@app.route('/login')
def login():
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    params = {
        'client_id':     CLIENT_ID,
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         'openid profile',
        'state':         state,
    }
    url = BASE_URL + '/oauth/authorize?' + '&'.join(f'{k}={v}' for k, v in params.items())
    return redirect(url)

@app.route('/callback')
def callback():
    if request.args.get('state') != session.get('oauth_state'):
        return 'State mismatch', 400
    if 'error' in request.args:
        return 'Access denied', 400

    token_res = requests.post(BASE_URL + '/oauth/token', data={
        'grant_type':    'authorization_code',
        'code':          request.args['code'],
        'redirect_uri':  REDIRECT_URI,
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })
    tokens = token_res.json()

    user_res = requests.get(BASE_URL + '/oauth/userinfo', headers={
        'Authorization': f"Bearer {tokens['access_token']}"
    })
    session['user']          = user_res.json()
    session['access_token']  = tokens['access_token']
    session['refresh_token'] = tokens['refresh_token']

    return redirect('/')
```
