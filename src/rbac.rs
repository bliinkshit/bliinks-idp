// src/rbac.rs
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use sqlx::PgPool;
use uuid::Uuid;

// internal
use crate::error::AppError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleInfo {
    pub id:          Uuid,
    pub name:        String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Default)]
struct Inner {
    by_id:   HashMap<Uuid, RoleInfo>,
    by_name: HashMap<String, Uuid>,
}

#[derive(Debug, Clone)]
pub struct RoleCache(Arc<RwLock<Inner>>);

impl RoleCache {
    pub fn empty() -> Self {
        Self(Arc::new(RwLock::new(Inner::default())))
    }

    pub fn populate(&self, roles: Vec<RoleInfo>) {
        let mut inner = self.0.write().unwrap();
        inner.by_id.clear();
        inner.by_name.clear();
        for role in roles {
            inner.by_name.insert(role.name.clone(), role.id);
            inner.by_id.insert(role.id, role);
        }
    }

    pub fn has_by_id(&self, role_id: &Uuid, permission: &str) -> bool {
        self.0
            .read()
            .unwrap()
            .by_id
            .get(role_id)
            .map(|r| r.permissions.iter().any(|p| p == permission))
            .unwrap_or(false)
    }

    pub fn id_for_name(&self, name: &str) -> Option<Uuid> {
        self.0.read().unwrap().by_name.get(name).copied()
    }

    pub fn name_for_id(&self, id: &Uuid) -> Option<String> {
        self.0.read().unwrap().by_id.get(id).map(|r| r.name.clone())
    }

    pub fn permissions_for_id(&self, role_id: &Uuid) -> Vec<String> {
        self.0
            .read()
            .unwrap()
            .by_id
            .get(role_id)
            .map(|r| r.permissions.clone())
            .unwrap_or_default()
    }

    pub async fn reload(&self, pool: &PgPool) -> Result<(), AppError> {
        let rows = load_from_db(pool).await?;
        self.populate(rows);
        Ok(())
    }
}

pub async fn load_from_db(pool: &PgPool) -> Result<Vec<RoleInfo>, AppError> {
    let roles = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, name FROM roles ORDER BY name ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if roles.is_empty() {
        return Ok(vec![]);
    }

    let mut result = Vec::with_capacity(roles.len());

    for (role_id, role_name) in roles {
        let perms = sqlx::query_as::<_, (String,)>(
            "SELECT p.name
             FROM permissions p
             INNER JOIN role_permissions rp ON rp.permission_id = p.id
             WHERE rp.role_id = $1",
        )
        .bind(role_id)
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        result.push(RoleInfo {
            id:          role_id,
            name:        role_name,
            permissions: perms.into_iter().map(|(p,)| p).collect(),
        });
    }

    Ok(result)
}
