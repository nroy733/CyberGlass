//! # Event Sender
//!
//! Sends events to CyberGlass via REST API or HEC endpoint.

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info};

/// Sends events to a CyberGlass server.
pub struct EventSender {
    client: Client,
    server: String,
    hec_token: Option<String>,
}

impl EventSender {
    /// Creates a new event sender.
    pub fn new(server: String, hec_token: Option<String>, timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("Failed to create HTTP client")?;

        info!("EventSender initialized for server: {}", server);

        Ok(Self {
            client,
            server,
            hec_token,
        })
    }

    /// Ping the server to verify connectivity.
    pub async fn ping(&self) -> Result<()> {
        let url = format!("{}/api/v1/health", self.server);
        let resp = self.client.get(&url).send().await?;
        if resp.status().is_success() {
            info!("CyberGlass server is reachable");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Server returned status {}", resp.status()))
        }
    }

    /// Send a single structured event via the REST ingest API.
    pub async fn send_event(
        &self,
        source: &str,
        source_type: &str,
        index: &str,
        event: Value,
    ) -> Result<()> {
        // Try HEC endpoint first if token is configured
        if let Some(token) = &self.hec_token {
            if let Err(e) = self
                .send_hec(source, source_type, index, event.clone(), token)
                .await
            {
                debug!("HEC send failed, falling back to REST: {}", e);
            } else {
                return Ok(());
            }
        }

        // Fall back to standard REST ingest
        self.send_rest(source, source_type, index, event).await
    }

    /// Send via REST /api/v1/ingest endpoint.
    async fn send_rest(
        &self,
        source: &str,
        source_type: &str,
        _index: &str,
        event: Value,
    ) -> Result<()> {
        let url = format!("{}/api/v1/ingest", self.server);

        // Serialize event to string for raw field
        let raw = serde_json::to_string(&event)?;

        let payload = serde_json::json!({
            "source": source,
            "source_type": source_type,
            "raw": raw,
        });

        let resp = self.client.post(&url).json(&payload).send().await?;
        let status = resp.status();
        if status.is_success() {
            debug!("Event sent via REST to {}", url);
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("REST ingest failed: {} {}", status, text))
        }
    }

    /// Send via HEC-compatible /services/collector endpoint.
    async fn send_hec(
        &self,
        source: &str,
        source_type: &str,
        index: &str,
        event: Value,
        token: &str,
    ) -> Result<()> {
        let url = format!("{}/services/collector", self.server);

        let payload = serde_json::json!({
            "event": event,
            "source": source,
            "sourcetype": source_type,
            "index": index,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("CyberGlass {}", token))
            .json(&payload)
            .send()
            .await?;
        let status = resp.status();

        if status.is_success() {
            debug!("Event sent via HEC to {}", url);
            Ok(())
        } else {
            let text = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("HEC ingest failed: {} {}", status, text))
        }
    }
}

impl Clone for EventSender {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            server: self.server.clone(),
            hec_token: self.hec_token.clone(),
        }
    }
}
