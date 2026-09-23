// src/error.rs
use axum::{http::StatusCode, response::{Html, IntoResponse, Response}};
use std::sync::Arc;
use tera::Context;

use crate::{render::render, AppState};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("template error: {0}")]
    Template(#[from] tera::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::NotFound       => StatusCode::NOT_FOUND,
            AppError::Forbidden      => StatusCode::FORBIDDEN,
            AppError::BadRequest(_)  => StatusCode::BAD_REQUEST,
            _                        => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status(), self.message()).into_response()
    }
}

pub struct AppErrorResponse(pub Arc<AppState>, pub AppError);

impl IntoResponse for AppErrorResponse {
    fn into_response(self) -> Response {
        let AppErrorResponse(state, err) = self;
        let status = err.status();

        let mut ctx = Context::new();
        ctx.insert("code",  &status.as_u16());
        ctx.insert("error", &err.message());

        let body = render(&state.tera, "error.html", &mut ctx, std::time::Instant::now())
            .unwrap_or_else(|_| format!("{} : {}", status, err.message()));

        (status, Html(body)).into_response()
    }
}
