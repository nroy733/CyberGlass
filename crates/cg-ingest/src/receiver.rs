//! # Syslog Network Receivers
//!
//! Provides high-throughput UDP and TCP syslog network listeners that
//! pipe incoming raw packets and streams directly through the CyberGlass
//! ingestion pipeline.

use crate::error::Result;
use crate::pipeline::IngestPipeline;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Network listener for receiving syslog over UDP and TCP.
pub struct SyslogReceiver {
    pipeline: Arc<IngestPipeline>,
}

impl SyslogReceiver {
    /// Creates a new `SyslogReceiver` bound to the given ingestion pipeline.
    pub fn new(pipeline: Arc<IngestPipeline>) -> Self {
        Self { pipeline }
    }

    /// Listens for incoming UDP syslog packets on `addr` until `shutdown` is signalled.
    pub async fn listen_udp(
        &self,
        addr: SocketAddr,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<()> {
        let socket = UdpSocket::bind(addr).await?;
        info!("Syslog UDP listener bound to {}", addr);

        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((size, peer)) => {
                            let payload = Bytes::copy_from_slice(&buf[..size]);
                            let pipeline = self.pipeline.clone();
                            let peer_str = peer.to_string();

                            tokio::spawn(async move {
                                if let Err(e) = pipeline.process_raw(payload, &peer_str, "syslog").await {
                                    warn!("Error processing UDP syslog from {}: {}", peer_str, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("UDP socket receive error: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("Syslog UDP listener on {} received shutdown signal", addr);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Listens for incoming TCP syslog connections on `addr` with newline framing.
    pub async fn listen_tcp(
        &self,
        addr: SocketAddr,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("Syslog TCP listener bound to {}", addr);

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((mut socket, peer)) => {
                            let pipeline = self.pipeline.clone();
                            let peer_str = peer.to_string();

                            tokio::spawn(async move {
                                let (reader, _) = socket.split();
                                let mut lines = BufReader::new(reader).lines();
                                while let Ok(Some(line)) = lines.next_line().await {
                                    if line.trim().is_empty() {
                                        continue;
                                    }
                                    let payload = Bytes::from(line.into_bytes());
                                    if let Err(e) = pipeline.process_raw(payload, &peer_str, "syslog").await {
                                        warn!("Error processing TCP syslog from {}: {}", peer_str, e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("TCP socket accept error: {}", e);
                        }
                    }
                }
                _ = shutdown.recv() => {
                    info!("Syslog TCP listener on {} received shutdown signal", addr);
                    break;
                }
            }
        }

        Ok(())
    }
}
