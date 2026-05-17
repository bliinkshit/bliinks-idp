// src/routes/settings.rs
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Form, Multipart, State},
    response::{Html, IntoResponse, Response},
};
use chrono::Utc;
use gif::{DecodeOptions, Encoder, Frame, Repeat};
use image::{imageops::FilterType, RgbaImage};
use serde::Deserialize;
use tera::Context;
use tokio::fs;

// internal
use crate::{
    db::{models::User, queries::{get_user_by_id, set_avatar_updated_at, update_user_color, update_user_display_name}},
    error::{AppError, AppErrorResponse},
    render::render,
    routes::{auth::USER_SESSION_KEY, avatar::AVATAR_DIR, error::render_error},
    session::Session,
    AppState,
    helpers::insert_user_ctx,
    render_err,
    render_server_error,
};

const AVATAR_SIZE:          u16   = 128;
const MAX_UPLOAD_BYTES:     usize = 5 * 1024 * 1024;
const MAX_SOURCE_DIM:       u32   = 8000;
const GIF_MAX_FRAMES:       usize = 200;
const MAX_DISPLAY_NAME_LEN: usize = 64;

fn is_valid_hex_color(s: &str) -> bool {
    let s = s.strip_prefix('#').unwrap_or(s);
    (s.len() == 6 || s.len() == 3) && s.chars().all(|c| c.is_ascii_hexdigit())
}

async fn settings_ctx(
    state:   &Arc<AppState>,
    user_id: &str,
) -> Result<(Context, User), AppError> {
    let user = get_user_by_id(&state.pool, user_id)
        .await?
        .ok_or_else(|| AppError::Internal("User not found".into()))?;

    let mut ctx = Context::new();
    ctx.insert("title",        "Settings");
    ctx.insert("id",           &user.id);
    ctx.insert("avatar",       &user.avatar_updated_at.is_some());
    ctx.insert("username",     &user.username);
    ctx.insert("display_name", &user.display_name);
    ctx.insert("color",        &user.color);
    insert_user_ctx(&mut ctx, &user, &state.roles);

    Ok((ctx, user))
}

pub async fn render_settings(
    session:      Session,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = match settings_ctx(&state, &user_id).await {
        Ok(v)  => v,
        Err(e) => return Ok(render_error(State(Arc::clone(&state)), session, e).await.into_response()),
    };

    render(&state.tera, "settings.html", &mut ctx, start)
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

#[derive(Deserialize)]
pub struct ProfileForm {
    pub display_name: String,
    pub color:        String,
}

pub async fn handle_profile(
    session:      Session,
    State(state): State<Arc<AppState>>,
    Form(form):   Form<ProfileForm>,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, user) = match settings_ctx(&state, &user_id).await {
        Ok(v)  => v,
        Err(e) => return Ok(render_error(State(Arc::clone(&state)), session, e).await.into_response()),
    };

    let name = form.display_name.trim();
    if name.len() > MAX_DISPLAY_NAME_LEN {
        render_err!(state, "settings.html", ctx, "Display name must be 64 characters or fewer.", start);
    }

    let new_name: Option<&str> = if name.is_empty() { None } else { Some(name) };
    if new_name != user.display_name.as_deref() {
        render_server_error!(update_user_display_name(&state.pool, &user_id, new_name).await, state, session);
    }

    let color = form.color.trim();
    let new_color: Option<String> = if color.is_empty() {
        None
    } else {
        if !is_valid_hex_color(color) {
            render_err!(state, "settings.html", ctx, "Color must be a valid hex value (e.g. #ff6b6b).", start);
        }
        Some(format!("#{}", color.strip_prefix('#').unwrap_or(color).to_lowercase()))
    };
    if new_color.as_deref() != user.color.as_deref() {
        render_server_error!(update_user_color(&state.pool, &user_id, new_color.as_deref()).await, state, session);
    }

    ctx.insert("display_name", &new_name);
    ctx.insert("color",        &new_color);
    ctx.insert("success",      "Profile updated.");

    render(&state.tera, "settings.html", &mut ctx, start)
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

pub async fn handle_upload(
    session:       Session,
    State(state):  State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Response, AppErrorResponse> {
    let start = Instant::now();

    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(axum::response::Redirect::to("/auth/login").into_response()),
    };

    let (mut ctx, _) = match settings_ctx(&state, &user_id).await {
        Ok(v)  => v,
        Err(e) => return Ok(render_error(State(Arc::clone(&state)), session, e).await.into_response()),
    };

    let data = loop {
        let field = match multipart.next_field().await {
            Ok(f)  => f,
            Err(e) => return Ok(render_error(State(state), session, AppError::Internal(format!("multipart error: {e}"))).await.into_response()),
        };

        match field {
            None => render_err!(state, "settings.html", ctx, "No avatar field in upload.", start),
            Some(field) if field.name() == Some("avatar") => {
                let bytes = match field.bytes().await {
                    Ok(b)  => b,
                    Err(e) => return Ok(render_error(State(state), session, AppError::Internal(format!("read error: {e}"))).await.into_response()),
                };

                if bytes.is_empty() {
                    render_err!(state, "settings.html", ctx, "Avatar field was empty.", start);
                }
                if bytes.len() > MAX_UPLOAD_BYTES {
                    render_err!(state, "settings.html", ctx, "File exceeds 5MB limit.", start);
                }

                break bytes;
            }
            Some(_) => continue,
        }
    };

    let data_vec  = data.to_vec();
    let gif_bytes = match tokio::task::spawn_blocking(move || {
        if is_gif(&data_vec) { process_gif(&data_vec) } else { process_static(&data_vec) }
    }).await {
        Ok(r)  => r,
        Err(e) => return Ok(render_error(State(state), session, AppError::Internal(e.to_string())).await.into_response()),
    };

    let gif_bytes = match gif_bytes {
        Ok(b)                          => b,
        Err(AppError::BadRequest(msg)) => render_err!(state, "settings.html", ctx, &msg, start),
        Err(e)                         => return Ok(render_error(State(state), session, e).await.into_response()),
    };

    render_server_error!(fs::create_dir_all(AVATAR_DIR).await, state, session);

    let tmp_path   = format!("{}/{}.gif.tmp", AVATAR_DIR, user_id);
    let final_path = format!("{}/{}.gif",     AVATAR_DIR, user_id);

    render_server_error!(fs::write(&tmp_path, &gif_bytes).await, state, session);
    render_server_error!(fs::rename(&tmp_path, &final_path).await, state, session);

    let ts = Utc::now().to_rfc3339();
    render_server_error!(set_avatar_updated_at(&state.pool, &user_id, &ts).await, state, session);

    ctx.insert("avatar",  &true);
    ctx.insert("success", "Avatar updated.");

    render(&state.tera, "settings.html", &mut ctx, start)
        .map(|html| Html(html).into_response())
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))
}

fn is_gif(data: &[u8]) -> bool {
    data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")
}

fn center_crop_resize_rgba(pixels: &[u8], src_w: u32, src_h: u32) -> Result<Vec<u8>, AppError> {
    let img = RgbaImage::from_raw(src_w, src_h, pixels.to_vec())
        .ok_or_else(|| AppError::Internal("failed to construct RgbaImage from frame".into()))?;

    let side    = src_w.min(src_h);
    let cropped = image::imageops::crop_imm(&img, (src_w - side) / 2, (src_h - side) / 2, side, side).to_image();
    let resized = image::imageops::resize(&cropped, AVATAR_SIZE as u32, AVATAR_SIZE as u32, FilterType::Lanczos3);

    Ok(resized.into_raw())
}

fn encode_gif(frames: Vec<(Vec<u8>, u16)>) -> Result<Vec<u8>, AppError> {
    let mut out = Vec::new();

    {
        let mut encoder = Encoder::new(&mut out, AVATAR_SIZE, AVATAR_SIZE, &[])
            .map_err(|e| AppError::Internal(format!("GIF encoder init: {e}")))?;

        encoder
            .set_repeat(Repeat::Infinite)
            .map_err(|e| AppError::Internal(format!("GIF repeat: {e}")))?;

        for (mut rgba, delay) in frames {
            let mut frame = Frame::from_rgba_speed(AVATAR_SIZE, AVATAR_SIZE, &mut rgba, 10);
            frame.delay   = delay;
            encoder
                .write_frame(&frame)
                .map_err(|e| AppError::Internal(format!("GIF frame write: {e}")))?;
        }
    }

    Ok(out)
}

fn process_gif(data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut opts = DecodeOptions::new();
    opts.set_color_output(gif::ColorOutput::RGBA);

    let mut decoder = opts
        .read_info(Cursor::new(data))
        .map_err(|e| AppError::BadRequest(format!("invalid GIF: {e}")))?;

    let src_w = decoder.width()  as u32;
    let src_h = decoder.height() as u32;

    if src_w > MAX_SOURCE_DIM || src_h > MAX_SOURCE_DIM {
        return Err(AppError::BadRequest(format!("GIF too large (max {MAX_SOURCE_DIM}px per side)")));
    }

    let mut canvas = vec![0u8; (src_w * src_h * 4) as usize];
    let mut frames: Vec<(Vec<u8>, u16)> = Vec::new();

    while let Some(frame) = decoder
        .read_next_frame()
        .map_err(|e| AppError::Internal(format!("GIF decode: {e}")))?
    {
        if frames.len() >= GIF_MAX_FRAMES {
            break;
        }

        let fx = frame.left   as u32;
        let fy = frame.top    as u32;
        let fw = frame.width  as u32;
        let fh = frame.height as u32;

        for row in 0..fh {
            for col in 0..fw {
                let src_i = ((row * fw + col) * 4) as usize;
                if src_i + 4 > frame.buffer.len() { continue; }

                let dst_x = fx + col;
                let dst_y = fy + row;
                if dst_x >= src_w || dst_y >= src_h { continue; }

                let dst_i = ((dst_y * src_w + dst_x) * 4) as usize;
                if dst_i + 4 > canvas.len() { continue; }

                if frame.buffer[src_i + 3] > 0 {
                    canvas[dst_i..dst_i + 4].copy_from_slice(&frame.buffer[src_i..src_i + 4]);
                }
            }
        }

        frames.push((center_crop_resize_rgba(&canvas, src_w, src_h)?, frame.delay));
    }

    if frames.is_empty() {
        return Err(AppError::BadRequest("GIF has no readable frames".into()));
    }

    encode_gif(frames)
}

fn process_static(data: &[u8]) -> Result<Vec<u8>, AppError> {
    let img = image::load_from_memory(data)
        .map_err(|e| AppError::BadRequest(format!("invalid image: {e}")))?;

    if img.width() > MAX_SOURCE_DIM || img.height() > MAX_SOURCE_DIM {
        return Err(AppError::BadRequest(format!("image too large (max {MAX_SOURCE_DIM}px per side)")));
    }

    let (w, h)  = (img.width(), img.height());
    let side    = w.min(h);
    let cropped = img.crop_imm((w - side) / 2, (h - side) / 2, side, side);
    let resized = cropped.resize_exact(AVATAR_SIZE as u32, AVATAR_SIZE as u32, FilterType::Lanczos3);

    encode_gif(vec![(resized.into_rgba8().into_raw(), 0)])
}
