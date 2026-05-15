// src/render.rs
use std::time::Instant;
use rand::seq::SliceRandom;
use tera::{Context, Tera};

// internal
use crate::cfg::CONFIG;
use crate::error::AppError;

const GEN_PHRASES: &[&str] = &[
    "rendered",
];

pub fn render(
    tera: &Tera,
    template: &str,
    ctx: &mut Context,
    start: Instant,
) -> Result<String, AppError> {
    let elapsed = start.elapsed().as_secs_f64();
    let phrase = GEN_PHRASES
        .choose(&mut rand::thread_rng())
        .unwrap_or(&"generated");
    let page = template
        .rsplit('/')
        .next()
        .unwrap_or(template)
        .trim_end_matches(".html");

    ctx.insert("title", &CONFIG.general.title);
    ctx.insert("gen_phrase", phrase);
    ctx.insert("gen_time_secs", &format!("{:.4}", elapsed));
    ctx.insert("page", page);

    Ok(tera.render(template, ctx)?)
}
