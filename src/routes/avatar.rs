// src/routes/avatar.rs
use std::io::Cursor;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use chrono::Utc;
use gif::{DecodeOptions, Encoder, Frame, Repeat};
use image::{imageops::FilterType, RgbaImage};
use tokio::fs;

use crate::{
    db::queries::{get_user_by_id, set_avatar_updated_at},
    error::{AppError, AppErrorResponse},
    routes::auth::USER_SESSION_KEY,
    session::Session,
    AppState,
};

pub const AVATAR_DIR:   &str  = "uploads/avatars";
const AVATAR_SIZE:      u16   = 128;
const MAX_UPLOAD_BYTES: usize = 5 * 1024 * 1024;
const MAX_SOURCE_DIM:   u32   = 8000;
const GIF_MAX_FRAMES:   usize = 200;

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

pub async fn handle_upload(
    session:       Session,
    State(state):  State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Response, AppErrorResponse> {
    let user_id: String = match session.get(USER_SESSION_KEY) {
        Some(id) => id,
        None     => return Ok(Redirect::to("/auth/login").into_response()),
    };

    let data = loop {
        let field = multipart
            .next_field()
            .await
            .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(format!("multipart error: {e}"))))?;

        match field {
            None => return Err(AppErrorResponse(Arc::clone(&state), AppError::BadRequest("no avatar field in upload".into()))),
            Some(field) if field.name() == Some("avatar") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(format!("read error: {e}"))))?;

                if bytes.len() > MAX_UPLOAD_BYTES {
                    return Err(AppErrorResponse(Arc::clone(&state), AppError::BadRequest("file exceeds 5MB limit".into())));
                }

                if bytes.is_empty() {
                    return Err(AppErrorResponse(Arc::clone(&state), AppError::BadRequest("avatar field was empty".into())));
                }

                break bytes;
            }
            Some(_) => continue,
        }
    };

    let data_vec = data.to_vec();
    let gif_bytes = tokio::task::spawn_blocking(move || {
        if is_gif(&data_vec) { process_gif(&data_vec) } else { process_static(&data_vec) }
    })
    .await
    .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(e.to_string())))?
    .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    fs::create_dir_all(AVATAR_DIR)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(format!("create dir: {e}"))))?;

    let tmp_path   = format!("{}/{}.gif.tmp", AVATAR_DIR, user_id);
    let final_path = format!("{}/{}.gif",     AVATAR_DIR, user_id);

    fs::write(&tmp_path, &gif_bytes)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(format!("write tmp: {e}"))))?;

    fs::rename(&tmp_path, &final_path)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), AppError::Internal(format!("rename: {e}"))))?;

    let ts = Utc::now().to_rfc3339();
    set_avatar_updated_at(&state.pool, &user_id, &ts)
        .await
        .map_err(|e| AppErrorResponse(Arc::clone(&state), e))?;

    Ok(Redirect::to("/settings").into_response())
}

pub async fn handle_serve(
    Path(user_id): Path<String>,
    State(state):  State<Arc<AppState>>,
    headers:       HeaderMap,
) -> Response {
    let user = match get_user_by_id(&state.pool, &user_id).await {
        Ok(Some(u)) => u,
        _           => return StatusCode::NOT_FOUND.into_response(),
    };

    let updated_at = match user.avatar_updated_at {
        Some(ts) => ts,
        None     => return StatusCode::NOT_FOUND.into_response(),
    };

    let etag = format!("\"{}\"", updated_at);

    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm == etag {
            return StatusCode::NOT_MODIFIED.into_response();
        }
    }

    let path = format!("{}/{}.gif", AVATAR_DIR, user_id);
    let data = match fs::read(&path).await {
        Ok(d)  => d,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE,  "image/gif")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::ETAG,          etag)
        .body(Body::from(data))
        .unwrap()
}
