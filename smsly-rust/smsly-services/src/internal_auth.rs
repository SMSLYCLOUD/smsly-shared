use crate::config::Settings;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use redis::{AsyncCommands, Client, Script};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InternalContext {
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub organization_id: Option<String>,
    #[serde(default = "default_account_type")]
    pub account_type: String,
    pub request_id: Option<String>,
    pub is_internal: bool,
}

fn default_account_type() -> String {
    "casual".to_string()
}

#[derive(Clone)]
pub struct AppState {
    pub redis: Option<Client>,
    pub settings: Settings,
}

pub async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    let skip_paths = ["/health", "/docs", "/redoc", "/openapi.json", "/metrics"];
    if skip_paths.iter().any(|p| path.starts_with(p)) {
        return Ok(next.run(request).await);
    }

    let headers = request.headers();
    let provided_secret = headers
        .get("X-Internal-Secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let internal_secret = &state.settings.internal_api_secret;

    if internal_secret.is_empty() {
        warn!("INTERNAL_API_SECRET not configured, allowing all requests");
    } else if !constant_time_eq(provided_secret.as_bytes(), internal_secret.as_bytes()) {
        warn!("Invalid internal secret from {:?}", request.uri());
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Unauthorized", "detail": "Invalid internal secret"})),
        )
            .into_response());
    }

    let context = InternalContext {
        user_id: headers
            .get("X-User-ID")
            .and_then(|h| h.to_str().ok())
            .map(String::from),
        user_email: headers
            .get("X-User-Email")
            .and_then(|h| h.to_str().ok())
            .map(String::from),
        organization_id: headers
            .get("X-Organization-ID")
            .and_then(|h| h.to_str().ok())
            .map(String::from),
        account_type: headers
            .get("X-Account-Type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("casual")
            .to_string(),
        request_id: headers
            .get("X-Request-ID")
            .and_then(|h| h.to_str().ok())
            .map(String::from),
        is_internal: true,
    };

    if let Some(redis_client) = &state.redis {
        let limiter = AccountTypeRateLimiter::new(redis_client.clone());
        if !limiter.check_rate_limit(&context).await {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Too Many Requests", "detail": "Rate limit exceeded"})),
            )
                .into_response());
        }
    }

    request.extensions_mut().insert(context.clone());

    let mut response = next.run(request).await;

    if let Some(req_id) = context.request_id {
        response
            .headers_mut()
            .insert("X-Request-ID", req_id.parse().unwrap());
    }

    Ok(response)
}

pub struct AccountTypeRateLimiter {
    redis: Client,
}

impl AccountTypeRateLimiter {
    pub fn new(redis: Client) -> Self {
        Self { redis }
    }

    pub async fn check_rate_limit(&self, context: &InternalContext) -> bool {
        let key_base = context
            .organization_id
            .as_deref()
            .or(context.user_id.as_deref())
            .unwrap_or("anonymous");

        let (limit_sec, limit_min) = match context.account_type.as_str() {
            "developer" => (20, 300),
            "enterprise" => (100, 1000),
            "reseller" => (50, 500),
            _ => (5, 60),
        };

        let mut conn = match self.redis.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Redis connection failed for rate limit: {}", e);
                return true;
            }
        };

        let script = Script::new(
            r#"
            local current = redis.call("INCR", KEYS[1])
            if current == 1 then
                redis.call("EXPIRE", KEYS[1], ARGV[1])
            end
            return current
        "#,
        );

        let second_key = format!("rate:{}:second", key_base);
        let current_sec: u64 = match script.key(&second_key).arg(1).invoke_async(&mut conn).await {
            Ok(v) => v,
            Err(_) => return true,
        };
        if current_sec > limit_sec {
            return false;
        }

        let minute_key = format!("rate:{}:minute", key_base);
        let current_min: u64 = match script
            .key(&minute_key)
            .arg(60)
            .invoke_async(&mut conn)
            .await
        {
            Ok(v) => v,
            Err(_) => return true,
        };
        if current_min > limit_min {
            return false;
        }

        true
    }
}
