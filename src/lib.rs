mod certs;
pub mod config;
mod multicast;

use std::net::Ipv4Addr;
use std::thread;
use std::thread::yield_now;
use std::time::Duration;
use log::info;
use crate::config::MulticastDiscoveryConfig;
use crate::multicast::{MulticastDiscoverySocket, PollResult};

pub struct Reprise {
}

impl Reprise {
    /// Create a new Reprise node running on local machine with enabled multicast discovery
    pub fn spawn_with_discovery(cfg: MulticastDiscoveryConfig) -> anyhow::Result<Self> {
        // Quic init
        let (cert, key) = certs::generate_self_signed_cert()?;
        let srv_config = quinn::ServerConfig::with_single_cert(vec![cert], key.into())?;
        let socket = quinn::Endpoint::server(srv_config, (Ipv4Addr::new(0, 0, 0, 0), 0).into())?;
        let socket_port = socket.local_addr()?.port();
        
        // multicast init
        let mut multicast_socket = MulticastDiscoverySocket::new(&cfg, socket_port)?;
        // handle multicast discovery in a separate thread
        thread::spawn(move || {
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
                }
            }
        });
        
        // handle incoming connections
        tokio::spawn(async move {
            while let Some(conn) = socket.accept().await {
                info!("New connection from {}", conn.remote_address());
                conn.refuse();
                
            }
        });


        Ok(Reprise {
            
        })
    }
}