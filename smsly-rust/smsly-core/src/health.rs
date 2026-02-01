use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use redis::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComponentHealth {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub service: String,
    pub version: String,
    pub components: HashMap<String, ComponentHealth>,
    pub timestamp: f64,
}

#[derive(Clone)]
pub struct HealthState {
    pub service_name: String,
    pub version: String,
    pub db_pool: Option<PgPool>,
    pub redis_client: Option<Client>,
}

async fn check_database(pool: &PgPool) -> ComponentHealth {
    let start = SystemTime::now();
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => {
            let duration = start.elapsed().unwrap_or_default().as_secs_f64() * 1000.0;
            ComponentHealth {
                status: "connected".to_string(),
                latency_ms: Some((duration * 100.0).round() / 100.0),
                error: None,
            }
        }
        Err(e) => {
            error!("Database health check failed: {}", e);
            ComponentHealth {
                status: "error".to_string(),
                latency_ms: None,
                error: Some(e.to_string()),
            }
        }
    }
}

async fn check_redis(client: &Client) -> ComponentHealth {
    let start = SystemTime::now();
    match client.get_multiplexed_async_connection().await {
        Ok(mut conn) => match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
            Ok(_) => {
                let duration = start.elapsed().unwrap_or_default().as_secs_f64() * 1000.0;
                ComponentHealth {
                    status: "connected".to_string(),
                    latency_ms: Some((duration * 100.0).round() / 100.0),
                    error: None,
                }
            }
            Err(e) => {
                error!("Redis PING failed: {}", e);
                ComponentHealth {
                    status: "error".to_string(),
                    latency_ms: None,
                    error: Some(e.to_string()),
                }
            }
        },
        Err(e) => {
            error!("Redis connection failed: {}", e);
            ComponentHealth {
                status: "error".to_string(),
                latency_ms: None,
                error: Some(e.to_string()),
            }
        }
    }
}

pub fn create_health_router(
    service_name: String,
    version: String,
    db_pool: Option<PgPool>,
    redis_client: Option<Client>,
) -> Router {
    let state = HealthState {
        service_name,
        version,
        db_pool,
        redis_client,
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/health/live", get(liveness_probe))
        .route("/health/ready", get(readiness_probe))
        .with_state(Arc::new(state))
}

async fn health_handler(State(state): State<Arc<HealthState>>) -> Json<HealthResponse> {
    let mut components = HashMap::new();
    let mut overall_status = HealthStatus::Healthy;

    if let Some(pool) = &state.db_pool {
        let h = check_database(pool).await;
        if h.status == "error" {
            overall_status = HealthStatus::Unhealthy;
        }
        components.insert("database".to_string(), h);
    }

    if let Some(client) = &state.redis_client {
        let h = check_redis(client).await;
        if h.status == "error" && overall_status == HealthStatus::Healthy {
            overall_status = HealthStatus::Degraded;
        }
        components.insert("redis".to_string(), h);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    Json(HealthResponse {
        status: overall_status,
        service: state.service_name.clone(),
        version: state.version.clone(),
        components,
        timestamp,
    })
}

async fn liveness_probe() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "alive"}))
}

async fn readiness_probe(State(state): State<Arc<HealthState>>) -> Response {
    if let Some(pool) = &state.db_pool {
        let h = check_database(pool).await;
        if h.status == "error" {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"status": "not_ready", "reason": "database_unavailable"})),
            )
                .into_response();
        }
    }
    (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))).into_response()
}
