use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Failed,
    Rejected,
}

impl Default for MessageStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SendResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    pub status: MessageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_response: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
    pub segments: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub provider_message_id: String,
    pub status: MessageStatus,
    pub timestamp: Option<f64>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub raw_payload: Option<Value>,
}

#[derive(Error, Debug)]
pub enum AdapterError {
    #[error("Unknown provider: {0}")]
    UnknownProvider(String),
}

#[async_trait]
pub trait BaseProviderAdapter: Send + Sync {
    fn name(&self) -> String;
    fn supports_mms(&self) -> bool {
        false
    }
    fn supports_whatsapp(&self) -> bool {
        false
    }
    fn supports_rcs(&self) -> bool {
        false
    }

    async fn initialize(&self) {
        info!("Provider adapter initialized: {}", self.name());
    }

    async fn close(&self) {
        info!("Provider adapter closed: {}", self.name());
    }

    async fn send_sms(
        &self,
        to: &str,
        from: &str,
        body: &str,
        metadata: Option<HashMap<String, Value>>,
    ) -> SendResult;

    async fn send_mms(
        &self,
        _to: &str,
        _from: &str,
        _text: Option<&str>,
        _media_urls: Vec<String>,
        _metadata: Option<HashMap<String, Value>>,
    ) -> SendResult {
        // Default implementation for providers that don't support MMS
        SendResult {
            success: false,
            status: MessageStatus::Failed,
            error_message: Some(format!("{} does not support MMS", self.name())),
            ..Default::default()
        }
    }

    async fn validate_webhook(&self, _headers: &HashMap<String, String>, _body: &[u8]) -> bool {
        true
    }

    async fn parse_webhook(&self, _body: &[u8]) -> Result<WebhookEvent, String> {
        Err(format!("{} must implement webhook parsing", self.name()))
    }

    async fn health_check(&self) -> bool {
        true
    }
}

pub struct ProviderRegistry {
    adapters: RwLock<HashMap<String, Arc<Box<dyn BaseProviderAdapter>>>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            adapters: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(&self, adapter: Box<dyn BaseProviderAdapter>) {
        let name = adapter.name().to_lowercase();
        info!("Provider registered: {}", name);
        self.adapters.write().await.insert(name, Arc::new(adapter));
    }

    pub async fn get(&self, name: &str) -> Result<Arc<Box<dyn BaseProviderAdapter>>, AdapterError> {
        let adapters = self.adapters.read().await;
        adapters
            .get(&name.to_lowercase())
            .cloned()
            .ok_or_else(|| AdapterError::UnknownProvider(name.to_string()))
    }

    pub async fn list(&self) -> Vec<String> {
        self.adapters.read().await.keys().cloned().collect()
    }
}
