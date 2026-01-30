use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: f64,
    pub service: String,
    pub event_type: String,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub payload: HashMap<String, serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub hash: String,
    pub previous_hash: Option<String>,
}

impl AuditEvent {
    pub fn new(
        service: String,
        event_type: String,
        action: String,
        actor_id: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            service,
            event_type,
            actor_id,
            actor_type: "system".to_string(),
            resource_type: None,
            resource_id: None,
            action,
            outcome: "success".to_string(),
            payload: HashMap::new(),
            ip_address: None,
            user_agent: None,
            hash: "".to_string(), // In real impl, compute hash
            previous_hash: None,
        }
    }
}
