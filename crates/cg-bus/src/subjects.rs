pub const EVENTS_RAW: &str = "events.raw.>";
pub const EVENTS_NORMALIZED: &str = "events.normalized.>";
pub const EVENTS_ENRICHED: &str = "events.enriched.>";
pub const ALERTS_NEW: &str = "alerts.new";
pub const ALERTS_UPDATED: &str = "alerts.updated";
pub const COMMANDS_INGEST: &str = "commands.ingest";
pub const COMMANDS_DETECT: &str = "commands.detect";
pub const METRICS: &str = "metrics.>";

pub fn event_raw_subject(source_type: &str) -> String {
    format!("events.raw.{}", source_type)
}

pub fn event_normalized_subject(index: &str) -> String {
    format!("events.normalized.{}", index)
}

pub fn event_enriched_subject(index: &str) -> String {
    format!("events.enriched.{}", index)
}
