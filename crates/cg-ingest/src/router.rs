use crate::error::Result;
use cg_bus::EventBus;
use cg_core::types::ParsedEvent;
use cg_proto::common::Event;

pub struct EventRouter {
    bus: EventBus,
}

impl EventRouter {
    pub fn new(bus: EventBus) -> Self {
        Self { bus }
    }

    pub async fn route(&self, event: &ParsedEvent) -> Result<()> {
        let proto_event = Event {
            id: event.id.clone(),
            timestamp: Some(prost_types::Timestamp {
                seconds: event.timestamp.timestamp(),
                nanos: event.timestamp.timestamp_subsec_nanos() as i32,
            }),
            ingest_time: Some(prost_types::Timestamp {
                seconds: event.ingest_time.timestamp(),
                nanos: event.ingest_time.timestamp_subsec_nanos() as i32,
            }),
            source: event.source.clone(),
            source_type: event.source_type.clone(),
            index: event.index.clone(),
            raw: event.raw.clone(),
            fields: event.fields.clone(),
            metadata: event.metadata.clone(),
            severity: event.severity as i32,
            tenant_id: "default".into(),
            collector_id: "core".into(),
        };

        self.bus.publish_event(&proto_event).await?;
        Ok(())
    }
}
