// src/bin/migrate_legacy.rs
use std::env;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{TimeZone, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use uuid::Uuid;

#[derive(Deserialize)]
struct LegacyDate {
    #[serde(rename = "$$date")]
    ms: i64,
}

#[derive(Deserialize)]
struct LegacyUser {
    username:   String,
    #[serde(rename = "isAdmin")]
    is_admin:   bool,
    status:     String,
    color:      Option<String>,
    #[serde(rename = "createdAt")]
    created_at: LegacyDate,
}

fn sanitize_username(raw: &str) -> (String, Option<String>) {
    let sanitized: String = raw
        .chars()
        .map(|c| if c == ' ' { '_' } else { c })
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect();

    let display_name = if sanitized != raw {
        Some(raw.to_string())
    } else {
        None
    };

    (sanitized, display_name)
}

fn ms_to_rfc3339(ms: i64) -> String {
    let secs  = ms / 1000;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339()
}

fn random_password_hash() -> String {
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing failed")
        .to_string()
}

async fn require_role_id(pool: &sqlx::SqlitePool, name: &str) -> anyhow::Result<String> {
    sqlx::query_scalar("SELECT id FROM roles WHERE name = ?")
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("role '{}' not found — run seed_rbac first", name))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: migrate_legacy <db_path> <legacy.json>");
        std::process::exit(1);
    }

    let db_url    = format!("sqlite:{}", args[1]);
    let json_path = &args[2];

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;

    let admin_role_id   = require_role_id(&pool, "admin").await?;
    let member_role_id  = require_role_id(&pool, "member").await?;
    let pending_role_id = require_role_id(&pool, "pending").await?;

    let data  = std::fs::read_to_string(json_path)?;
    let users: Vec<LegacyUser> = serde_json::from_str(&data)?;

    let mut inserted = 0;
    let mut skipped  = 0;

    for legacy in users {
        let (username, display_name) = sanitize_username(&legacy.username);

        if username.is_empty() {
            eprintln!("skip: '{}' sanitizes to empty string", legacy.username);
            skipped += 1;
            continue;
        }

        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)",
        )
        .bind(&username)
        .fetch_one(&pool)
        .await?;

        if exists {
            eprintln!("skip: username '{}' already exists", username);
            skipped += 1;
            continue;
        }

        let role_id = if legacy.is_admin {
            &admin_role_id
        } else if legacy.status == "approved" {
            &member_role_id
        } else {
            &pending_role_id
        };

        let id           = Uuid::new_v4().to_string();
        let password     = random_password_hash();
        let date_created = ms_to_rfc3339(legacy.created_at.ms);
        let color        = legacy.color.filter(|c| !c.is_empty());

        sqlx::query(
            "INSERT INTO users
                (id, username, password, role, display_name, color, avatar_updated_at, date_created)
             VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
        )
        .bind(&id)
        .bind(&username)
        .bind(&password)
        .bind(role_id)
        .bind(&display_name)
        .bind(&color)
        .bind(&date_created)
        .execute(&pool)
        .await?;

        println!(
            "inserted: '{}' (display: {:?}, role: {})",
            username,
            display_name,
            if legacy.is_admin { "admin" } else if legacy.status == "approved" { "member" } else { "pending" },
        );
        inserted += 1;
    }

    println!("\ndone — inserted: {}, skipped: {}", inserted, skipped);
    Ok(())
}
