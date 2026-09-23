// src/bin/migrate_legacy.rs
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{TimeZone, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
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

fn ms_to_datetime(ms: i64) -> chrono::DateTime<Utc> {
    let secs  = ms / 1000;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(Utc::now)
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

async fn require_role_id(pool: &sqlx::PgPool, name: &str) -> anyhow::Result<Uuid> {
    sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("role '{}' not found — run seed_rbac first.", name))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let db_url    = args.next().expect("usage: migrate_legacy <postgres_url> <legacy.json>");
    let json_path = args.next().expect("usage: migrate_legacy <postgres_url> <legacy.json>");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;

    let admin_role_id   = require_role_id(&pool, "admin").await?;
    let member_role_id  = require_role_id(&pool, "member").await?;
    let pending_role_id = require_role_id(&pool, "pending").await?;

    let data  = std::fs::read_to_string(&json_path)?;
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
            "SELECT EXISTS(SELECT 1 FROM users WHERE username ILIKE $1)",
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
            admin_role_id
        } else if legacy.status == "approved" {
            member_role_id
        } else {
            pending_role_id
        };

        let id           = Uuid::new_v4();
        let password     = random_password_hash();
        let date_created = ms_to_datetime(legacy.created_at.ms);
        let color        = legacy.color.filter(|c| !c.is_empty());

        sqlx::query(
            "INSERT INTO users
                (id, username, password, role, display_name, color, avatar_updated_at, date_created)
             VALUES ($1, $2, $3, $4, $5, $6, NULL, $7)",
        )
        .bind(id)
        .bind(&username)
        .bind(&password)
        .bind(role_id)
        .bind(&display_name)
        .bind(&color)
        .bind(date_created)
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
