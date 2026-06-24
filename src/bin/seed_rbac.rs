// src/bin/seed_rbac.rs
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

struct Role {
    name:        &'static str,
    description: &'static str,
    permissions: &'static [&'static str],
}

const ROLES: &[Role] = &[
    Role {
        name:        "deleted",
        description: "Soft-deleted account, no access.",
        permissions: &[],
    },
    Role {
        name:        "banned",
        description: "Banned account, no access, data retained.",
        permissions: &[],
    },
    Role {
        name:        "pending",
        description: "Awaiting admin approval.",
        permissions: &[],
    },
    Role {
        name:        "member",
        description: "Standard user.",
        permissions: &["login", "edit_self", "reset_own_pw"],
    },
    Role {
        name:        "admin",
        description: "Full administrative access.",
        permissions: &[
            "login",
            "edit_self",
            "reset_own_pw",
            "access_admin",
            "edit_users",
            "approve_users",
            "ban_users",
            "delete_users",
            "reset_any_pw",
            "manage_clients",
            "manage_admins",
        ],
    },
];

struct Permission {
    name:        &'static str,
    description: &'static str,
}

const PERMISSIONS: &[Permission] = &[
    Permission { name: "login",          description: "Can authenticate." },
    Permission { name: "edit_self",      description: "Can edit own profile." },
    Permission { name: "reset_own_pw",   description: "Can request own password reset." },
    Permission { name: "access_admin",   description: "Can access the admin panel." },
    Permission { name: "edit_users",     description: "Can edit any user profile." },
    Permission { name: "approve_users",  description: "Can approve or unapprove pending accounts." },
    Permission { name: "ban_users",      description: "Can ban or unban accounts." },
    Permission { name: "delete_users",   description: "Can delete accounts." },
    Permission { name: "reset_any_pw",   description: "Can issue password resets for any user." },
    Permission { name: "manage_clients", description: "Can create and delete OAuth clients." },
    Permission { name: "manage_admins",  description: "Can promote or demote admins." },
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_url = std::env::args().nth(1)
        .expect("usage: seed_rbac <postgres_url>");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;

    for perm in PERMISSIONS {
        let existing: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM permissions WHERE name = $1)",
        )
        .bind(perm.name)
        .fetch_one(&pool)
        .await?;

        if existing {
            println!("permission exists, skipping: {}", perm.name);
            continue;
        }

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO permissions (id, name, description) VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind(perm.name)
        .bind(perm.description)
        .execute(&pool)
        .await?;

        println!("inserted permission: {}", perm.name);
    }

    for role in ROLES {
        let existing: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)",
        )
        .bind(role.name)
        .fetch_one(&pool)
        .await?;

        if existing {
            println!("role exists, skipping: {}", role.name);
            continue;
        }

        let role_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO roles (id, name, description) VALUES ($1, $2, $3)",
        )
        .bind(role_id)
        .bind(role.name)
        .bind(role.description)
        .execute(&pool)
        .await?;

        println!("inserted role: {}", role.name);

        for perm_name in role.permissions {
            let perm_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM permissions WHERE name = $1",
            )
            .bind(perm_name)
            .fetch_optional(&pool)
            .await?;

            match perm_id {
                Some(pid) => {
                    sqlx::query(
                        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
                    )
                    .bind(role_id)
                    .bind(pid)
                    .execute(&pool)
                    .await?;
                    println!("  -> granted: {}", perm_name);
                }
                None => eprintln!("  -> permission not found, skipping: {}", perm_name),
            }
        }
    }

    println!("\ndone.");
    Ok(())
}
