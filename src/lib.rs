mod certs;
pub mod config;
pub mod multicast;

use std::net::Ipv4Addr;
use std::thread;
use std::thread::yield_now;
use std::time::Duration;
use log::info;
use quinn::Endpoint;
use crate::config::MulticastDiscoveryConfig;
use crate::multicast::{MulticastDiscoverySocket, PollResult};

pub struct Reprise {
    endpoint: Endpoint,
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
        // handle multicast discovery in a separate thread
        let jh = thread::Builder::new().name("[Reprise accept]".to_string()).spawn(move || {
            loop {
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
            endpoint
        })
    }
}