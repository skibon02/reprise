mod certs;
pub mod config;
pub mod multicast;

use std::net::Ipv4Addr;
use std::thread;
use std::thread::yield_now;
use std::time::Duration;
use log::info;
use quinn::Endpoint;
use tokio::sync::watch;
use tokio::sync::watch::Sender;
use crate::config::MulticastDiscoveryConfig;
use crate::multicast::{MulticastDiscoverySocket, PollResult};

pub struct Reprise {
    endpoint: Endpoint,
    discover_signal: Sender<u32>,
}

impl Reprise {
    /// Create a new Reprise node running on local machine with enabled multicast discovery on all interfaces
    /// 
    /// Possible fail reasons:
    /// - failure to generate certificate
    /// - failure to load certificate
    /// - Failure to create quinn endpoint
    /// - failure to initialize multicast discovery socket
    /// - failure to spawn accept thread
    pub fn new_node(cfg: MulticastDiscoveryConfig) -> anyhow::Result<Self> {
        // Quic init
        let (cert, key) = certs::generate_self_signed_cert()?;
        let srv_config = quinn::ServerConfig::with_single_cert(vec![cert], key.into())?;
        let endpoint = Endpoint::server(srv_config, (Ipv4Addr::new(0, 0, 0, 0), 0).into())?;
        let socket_port = endpoint.local_addr()?.port();
        
        // multicast init
        let mut multicast_socket = MulticastDiscoverySocket::new(&cfg, socket_port)?;
        let (discover_tx, mut discover_rx) = watch::channel(0);
        // handle multicast discovery in a separate thread
        let jh = thread::Builder::new().name("[Reprise accept]".to_string()).spawn(move || {
            info!("Multicast discovery running! discover_id: {:x}, port: {:?}", multicast_socket.discover_id(), multicast_socket.running_port());
            loop {
                if discover_rx.has_changed().unwrap() {
                    discover_rx.mark_unchanged();
                    multicast_socket.discover()
                }
                match multicast_socket.poll() { 
                    PollResult::Nothing => {
                        thread::sleep(Duration::from_millis(10));
                        yield_now();
                    }
                    PollResult::DiscoveredClient {
                        addr,
                        discover_id
                    } => {
                        info!("\t\tMulticast discovery: Discovered client at {addr} - {:x}", discover_id);
                    }
                    PollResult::DisconnectedClient {
                        addr,
                        discover_id
                    } => {
                        info!("\t\tMulticast discovery: Disconnected client at {addr} - {:x}", discover_id);
                    }
                }
            }
        })?;
        
        // handle incoming connections in a separate task
        let endpoint_connection = endpoint.clone();
        tokio::spawn(async move {
            while let Some(conn) = endpoint_connection.accept().await {
                info!("New connection from {}", conn.remote_address());
                conn.refuse();
            }
        });

        Ok(Reprise {
            endpoint,
            discover_signal: discover_tx,
        })
    }
    
    pub fn discover(&self) {
        self.discover_signal.send_modify(|v| *v = v.wrapping_add(1))
    }
}