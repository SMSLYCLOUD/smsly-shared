use crate::adapters::base_adapter::BaseAdapter;
use crate::config::Settings;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::SystemTime;
use tracing::{info, warn};

#[derive(Serialize, Deserialize, Debug)]
pub struct SMSResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sms_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct SMSAdapter {
    base: BaseAdapter,
}

impl SMSAdapter {
    pub fn new(settings: Settings) -> Self {
        Self {
            base: BaseAdapter::new("sms".to_string(), settings),
        }
    }

    pub async fn send_sms(
        &self,
        to: &str,
        message: &str,
        account_id: &str,
        project_id: Option<&str>,
        from_number: Option<&str>,
    ) -> SMSResponse {
        let start = SystemTime::now();
        let result = if self.base.use_microservice {
            self.send_via_microservice(to, message, account_id, project_id, from_number)
                .await
        } else {
            self.send_via_legacy(to, message, account_id, project_id, from_number)
                .await
        };

        let duration = start.elapsed().unwrap_or_default().as_secs_f64();
        self.base
            .track_request("send_sms", &result.provider, result.success, duration, None);

        result
    }

    async fn send_via_microservice(
        &self,
        to: &str,
        message: &str,
        account_id: &str,
        project_id: Option<&str>,
        from_number: Option<&str>,
    ) -> SMSResponse {
        info!("Attempting send via microservice");

        if self.base.fallback_enabled {
            warn!("Microservice failed/unavailable, falling back to legacy");
            return self
                .send_via_legacy(to, message, account_id, project_id, from_number)
                .await;
        }

        SMSResponse {
            success: false,
            sms_id: None,
            status: None,
            provider: "microservice".to_string(),
            data: None,
            error: Some("Microservice unavailable".to_string()),
        }
    }

    async fn send_via_legacy(
        &self,
        _to: &str,
        _message: &str,
        _account_id: &str,
        _project_id: Option<&str>,
        _from_number: Option<&str>,
    ) -> SMSResponse {
        warn!("Legacy service not available in Rust port");
        SMSResponse {
            success: false,
            sms_id: None,
            status: None,
            provider: "legacy".to_string(),
            data: None,
            error: Some("Legacy service not available".to_string()),
        }
    }
}
