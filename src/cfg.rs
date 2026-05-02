// src/cfg.rs
use std::net::SocketAddr;
use serde::Deserialize;
use once_cell::sync::Lazy;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server:   Server,
    pub general:  General,
    pub database: Database,
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct General {
    pub title: String,
    pub dev:   bool,
}

#[derive(Debug, Deserialize)]
pub struct Database {
    pub url: String,
}

impl Server {
    pub fn addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("Invalid socket address")
    }
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    let settings = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .add_source(config::Environment::with_prefix("APP"))
        .build()
        .expect("Failed to load config");

    settings.try_deserialize().expect("Invalid config")
});
