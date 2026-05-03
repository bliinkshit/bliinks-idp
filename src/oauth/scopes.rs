// src/oauth/scopes.rs
use std::collections::HashSet;

pub const OPENID:  &str = "openid";
pub const PROFILE: &str = "profile";

const VALID: &[&str] = &[OPENID, PROFILE];

pub fn parse(raw: &str) -> HashSet<String> {
    raw.split_whitespace()
        .filter(|s| VALID.contains(s))
        .map(String::from)
        .collect()
}

pub fn serialize(scopes: &HashSet<String>) -> String {
    let mut v: Vec<&str> = scopes.iter().map(String::as_str).collect();
    v.sort();
    v.join(" ")
}

pub fn contains(stored: &str, scope: &str) -> bool {
    stored.split_whitespace().any(|s| s == scope)
}
