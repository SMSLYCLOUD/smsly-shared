use crate::config::Settings;
use serde_json::Value;
use smsly_core::metrics::track_metric;
use std::collections::HashMap;

pub struct BaseAdapter {
    pub service_name: String,
    pub settings: Settings,
    pub use_microservice: bool,
    pub fallback_enabled: bool,
}

impl BaseAdapter {
    pub fn new(service_name: String, settings: Settings) -> Self {
        let use_microservice = settings.is_microservice_enabled(&service_name);
        let fallback_enabled = settings.is_fallback_enabled(&service_name);

        Self {
            service_name,
            settings,
            use_microservice,
            fallback_enabled,
        }
    }

    pub fn track_request(
        &self,
        operation: &str,
        provider: &str,
        success: bool,
        duration: f64,
        metadata: Option<HashMap<String, Value>>,
    ) {
        let mut meta = metadata.unwrap_or_default();
        meta.insert(
            "service".to_string(),
            Value::String(self.service_name.clone()),
        );
        meta.insert(
            "operation".to_string(),
            Value::String(operation.to_string()),
        );
        meta.insert("provider".to_string(), Value::String(provider.to_string()));
        meta.insert("success".to_string(), Value::Bool(success));
        if let Some(n) = serde_json::Number::from_f64(duration * 1000.0) {
            meta.insert("duration_ms".to_string(), Value::Number(n));
        }

        track_metric("adapter.request", meta);
    }
}
