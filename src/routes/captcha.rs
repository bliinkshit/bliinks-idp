// src/routes/captcha.rs
use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::header,
    response::Response,
};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use yaptcha::{Captcha, captcha::CaptchaConfig};

// internal
use crate::{
    error::AppErrorResponse,
    session::Session,
    AppState,
};

pub const CAPTCHA_SESSION_KEY: &str = "captcha_hash";

pub async fn render_captcha(
    mut session:    Session,
    State(_state):  State<Arc<AppState>>,
) -> Result<Response<Body>, AppErrorResponse> {
    let (answer, hash) = {
        let mut rng = rand::thread_rng();
        let answer: String = (0..6)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect::<String>();
        let hash = hex::encode(Sha256::digest(answer.to_uppercase().as_bytes()));
        (answer, hash)
    };

    session.insert(CAPTCHA_SESSION_KEY, &hash);
    session.save().await;

    let captcha = Captcha::with_config(CaptchaConfig {
        width:              160,
        height:             50,
        noise_dots:         150,
        noise_lines:        4,
        fuzz_radius:        3,
        ghost_grid_spacing: 22,
        wave_amplitude:     4.0,
        wave_frequency:     0.06,
        ..Default::default()
    });

    let img         = captcha.generate(&answer);
    let secure      = !crate::cfg::CONFIG.general.dev;
    let cookie      = session.cookie_header(secure);

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "image/png")
        .header(header::SET_COOKIE, cookie)
        .body(Body::from(img.into_bytes()))
        .unwrap())
}
