use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricLabels {
    pub service: String,
    pub environment: String,
    pub version: String,
}

impl Default for MetricLabels {
    fn default() -> Self {
        Self {
            service: "unknown".to_string(),
            environment: "production".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

pub struct SimpleMetrics {
    labels: MetricLabels,
    counters: Mutex<HashMap<String, i64>>,
    gauges: Mutex<HashMap<String, f64>>,
    histograms: Mutex<HashMap<String, Vec<f64>>>,
}

impl SimpleMetrics {
    pub fn new(labels: Option<MetricLabels>) -> Self {
        Self {
            labels: labels.unwrap_or_default(),
            counters: Mutex::new(HashMap::new()),
            gauges: Mutex::new(HashMap::new()),
            histograms: Mutex::new(HashMap::new()),
        }
    }

    fn make_key(&self, name: &str, labels: &Option<HashMap<String, String>>) -> String {
        if let Some(l) = labels {
            let mut sorted_labels: Vec<_> = l.iter().collect();
            sorted_labels.sort_by_key(|a| a.0);
            let label_str: Vec<String> = sorted_labels
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            format!("{}{{{}}}", name, label_str.join(","))
        } else {
            name.to_string()
        }
    }

    pub fn increment(&self, name: &str, value: i64, labels: Option<HashMap<String, String>>) {
        let key = self.make_key(name, &labels);
        let mut counters = self.counters.lock().unwrap();
        *counters.entry(key).or_insert(0) += value;
    }

    pub fn set_gauge(&self, name: &str, value: f64, labels: Option<HashMap<String, String>>) {
        let key = self.make_key(name, &labels);
        let mut gauges = self.gauges.lock().unwrap();
        gauges.insert(key, value);
    }

    pub fn observe(&self, name: &str, value: f64, labels: Option<HashMap<String, String>>) {
        let key = self.make_key(name, &labels);
        let mut histograms = self.histograms.lock().unwrap();
        histograms.entry(key).or_default().push(value);
    }

    fn percentile(sorted_values: &[f64], percentile: f64) -> f64 {
        if sorted_values.is_empty() {
            return 0.0;
        }
        let idx = (sorted_values.len() as f64 * percentile / 100.0) as usize;
        sorted_values[std::cmp::min(idx, sorted_values.len() - 1)]
    }

    pub fn get_histogram_stats(
        &self,
        name: &str,
        labels: Option<HashMap<String, String>>,
    ) -> HashMap<String, f64> {
        let key = self.make_key(name, &labels);
        let histograms = self.histograms.lock().unwrap();

        let mut stats = HashMap::new();
        if let Some(values) = histograms.get(&key) {
            let mut sorted_values = values.clone();
            sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let count = sorted_values.len() as f64;
            let sum: f64 = sorted_values.iter().sum();

            stats.insert("count".to_string(), count);
            stats.insert("sum".to_string(), sum);
            stats.insert(
                "avg".to_string(),
                if count > 0.0 { sum / count } else { 0.0 },
            );
            stats.insert("p50".to_string(), Self::percentile(&sorted_values, 50.0));
            stats.insert("p95".to_string(), Self::percentile(&sorted_values, 95.0));
            stats.insert("p99".to_string(), Self::percentile(&sorted_values, 99.0));
        } else {
            stats.insert("count".to_string(), 0.0);
            stats.insert("sum".to_string(), 0.0);
            stats.insert("avg".to_string(), 0.0);
            stats.insert("p50".to_string(), 0.0);
            stats.insert("p95".to_string(), 0.0);
            stats.insert("p99".to_string(), 0.0);
        }
        stats
    }
}

lazy_static! {
    pub static ref GLOBAL_METRICS: SimpleMetrics = SimpleMetrics::new(None);
}

pub fn track_metric(name: &str, metadata: HashMap<String, serde_json::Value>) {
    let mut labels = HashMap::new();
    let mut val = 1.0;

    for (k, v) in metadata {
        if let Some(n) = v.as_f64() {
            if k == "duration_ms" || k == "latency" || k == "value" {
                val = n;
            }
        }
        if let Some(s) = v.as_str() {
            labels.insert(k, s.to_string());
        } else {
            labels.insert(k, v.to_string());
        }
    }

    GLOBAL_METRICS.observe(name, val, Some(labels));
}

pub struct Timer<'a> {
    metrics: &'a SimpleMetrics,
    name: String,
    labels: Option<HashMap<String, String>>,
    start: Option<SystemTime>,
}

impl<'a> Timer<'a> {
    pub fn new(
        metrics: &'a SimpleMetrics,
        name: &str,
        labels: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            metrics,
            name: name.to_string(),
            labels,
            start: None,
        }
    }

    pub fn start(&mut self) {
        self.start = Some(SystemTime::now());
    }

    pub fn stop(&self) {
        if let Some(start) = self.start {
            let duration = start.elapsed().unwrap_or_default().as_secs_f64();
            self.metrics
                .observe(&self.name, duration, self.labels.clone());
        }
    }
}

pub struct MetricNames;

impl MetricNames {
    pub const HTTP_REQUESTS_TOTAL: &'static str = "http_requests";
    pub const HTTP_REQUEST_DURATION: &'static str = "http_request_duration_seconds";
    pub const MESSAGES_SENT_TOTAL: &'static str = "smsly_messages_sent";
}
