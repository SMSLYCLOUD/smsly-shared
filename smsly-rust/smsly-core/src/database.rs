use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::OnceLock;
use tracing::info;

static POOL: OnceLock<PgPool> = OnceLock::new();

pub async fn create_async_engine(
    database_url: &str,
    pool_size: u32,
    _max_overflow: u32,
    _pool_pre_ping: bool,
    _echo: bool,
) -> Result<&'static PgPool, sqlx::Error> {
    if POOL.get().is_some() {
        return Ok(POOL.get().unwrap());
    }

    let pool = PgPoolOptions::new()
        .max_connections(pool_size)
        .connect(database_url)
        .await?;

    match POOL.set(pool) {
        Ok(_) => {
            info!("Database engine initialized with pool_size={}", pool_size);
            Ok(POOL.get().unwrap())
        }
        Err(_) => Ok(POOL.get().unwrap()),
    }
}

pub fn get_engine() -> &'static PgPool {
    POOL.get()
        .expect("Database engine not initialized. Call create_async_engine() first.")
}

pub async fn get_db() -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, sqlx::Error> {
    let pool = get_engine();
    pool.acquire().await
}

pub async fn close_engine() {
    if let Some(pool) = POOL.get() {
        pool.close().await;
        info!("Database engine closed");
    }
}
