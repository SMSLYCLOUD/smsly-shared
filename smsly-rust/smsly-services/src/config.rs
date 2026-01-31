use std::env;

#[derive(Clone)]
pub struct Settings {
    pub internal_api_secret: String,
}

impl Settings {
    pub fn new() -> Self {
        dotenvy::dotenv().ok();

        Self {
            internal_api_secret: env::var("INTERNAL_API_SECRET").unwrap_or_default(),
        }
    }

    pub fn is_microservice_enabled(&self, service_name: &str) -> bool {
        env::var(format!("USE_{}_MICROSERVICE", service_name.to_uppercase()))
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false)
    }

    pub fn is_fallback_enabled(&self, service_name: &str) -> bool {
        env::var(format!(
            "{}_MICROSERVICE_FALLBACK",
            service_name.to_uppercase()
        ))
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(true)
    }
}
