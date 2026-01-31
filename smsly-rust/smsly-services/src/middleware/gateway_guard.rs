// Placeholder for gateway guard middleware
// Would ensure requests come from the gateway (e.g. check specific headers or IPs)

use axum::{
    middleware::Next,
    response::Response,
    extract::Request,
};

pub async fn gateway_guard_middleware(
    request: Request,
    next: Next,
) -> Response {
    // Check if request is allowed (e.g. from gateway)
    next.run(request).await
}
