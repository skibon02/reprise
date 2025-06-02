use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use if_addrs::get_if_addrs;
use log::{info, warn};
use multicast_socket::{all_ipv4_interfaces, Interface, Message, MulticastOptions, MulticastSocket};
use sha2::Digest;
use tokio::time::Instant;
use crate::config::MulticastDiscoveryConfig;

const SEND_DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

pub struct MulticastDiscoverySocket {
    socket: MulticastSocket,
    local_port: u16,
    cfg: MulticastDiscoveryConfig,
    multicast_own_port: u16,

    // state machine
    send_discovery_tm: BTreeMap<Ipv4Addr, Instant>
}

impl MulticastDiscoverySocket {
    pub fn new(cfg: &MulticastDiscoveryConfig, local_port: u16) -> anyhow::Result<Self> {
        let options = MulticastOptions {
            read_timeout: Some(Duration::from_millis(10)),
            ..Default::default()
        };

        let multicast_own_port = cfg.multicast_port;
        let socket = MulticastSocket::with_options(
            SocketAddrV4::new(cfg.multicast_group_ip, multicast_own_port),
            all_ipv4_interfaces()?,
            options
        )?;

        Ok(Self {
            socket,
            local_port,
            cfg: cfg.clone(),
            multicast_own_port,

            send_discovery_tm: BTreeMap::new(),
        })
    }


    pub fn poll(&mut self) -> PollResult {
        self.try_poll().unwrap_or(PollResult::Nothing)
    }
    fn try_poll(&mut self) -> Option<PollResult> {
        // 1. Send discovery messages if needed
        for interface in all_interfaces() {
            if let Some(tm) = self.send_discovery_tm.get(&interface) {
                if Instant::now() < *tm + SEND_DISCOVERY_INTERVAL {
                    continue; // skip if not time yet
                }
            }

            // send discovery message
            let msg = DiscoveryMessage::Discovery.gen_message();
            if let Err(e) = self.socket.send(&msg, &Interface::Ip(interface)) {
                warn!("Failed to send discovery message to interface {}: {}", interface, e);
            } else {
                info!("Sent discovery message to interface {}", interface);
                self.send_discovery_tm.insert(interface, Instant::now());
            }
        }

        // 2. Handle incoming messages
        if let Ok(Message {
                data,
                origin_address,
                interface
             }) = self.socket.receive() {

            let interface_ip = match interface {
                Interface::Ip(ip) => Some(ip),
                Interface::Index(i) => {
                    get_ip_from_ifindex(i)
                }
                _ => None
            };

            // Our own address, ignoring
            if all_interfaces().contains(&origin_address.ip()) && origin_address.port() == self.multicast_own_port  {
                return None;
            }
            
            match DiscoveryMessage::try_parse(&data) {
                Some(DiscoveryMessage::Discovery) => {
                    info!("Received discovery message from {}", origin_address);
                    // Respond with a hello message
                    let hello_msg = DiscoveryMessage::DiscoverHello { local_port: self.local_port }.gen_message();
                    if let Err(e) = self.socket.send(&hello_msg, &interface) {
                        warn!("Failed to send hello message to {}: {}", origin_address, e);
                    } else {
                        info!("Sent hello message to {}", origin_address);
                    }

                    // prolong the discovery timer for this interface
                    if let Some(ip) = interface_ip {
                        info!("\tUpdating interface {}", ip);
                        self.send_discovery_tm.insert(ip, Instant::now() + Duration::from_millis(500));
                    }

                    None
                }
                Some(DiscoveryMessage::DiscoverHello { local_port }) => {
                    
                    Some(PollResult::DiscoveredClient {
                        addr: origin_address
                    })
                }
                None => {
                    warn!("Received unknown message from {}: {:?}", origin_address, data);
                    None
                }
            }
        }
        else {
            None
        }
    }
}
fn get_ip_from_ifindex(ifindex: i32) -> Option<Ipv4Addr> {
    // Iterate through all interfaces
    for iface in get_if_addrs().ok()? {
        if iface.index == Some(ifindex as u32) {
            let IpAddr::V4(ipv4) = iface.ip() else {
                return None;
            };

            return Some(ipv4);
        }
    }
    None
}
fn all_interfaces() -> Vec<Ipv4Addr> {
    all_ipv4_interfaces().unwrap_or_default()
}

#[derive(Copy, Clone)]
pub enum DiscoveryMessage {
    Discovery,
    DiscoverHello {
        local_port: u16,
    }
}

impl DiscoveryMessage {
    fn header(&self) -> &'static [u8] {
        match self {
            DiscoveryMessage::Discovery => b"discovery",
            DiscoveryMessage::DiscoverHello { .. } => b"discovery-hello",
        }
    }
    fn try_parse(msg: &[u8]) -> Option<Self> {
        if msg.starts_with(DiscoveryMessage::Discovery.header())
            && msg.len() == DiscoveryMessage::Discovery.header().len() + 32
            && msg.ends_with(sha2::Sha256::digest(&msg[..msg.len() - 32]).as_ref()) {
            Some(DiscoveryMessage::Discovery)
        } else if msg.starts_with(DiscoveryMessage::DiscoverHello { local_port: 0 }.header())
            && msg.len() == (DiscoveryMessage::DiscoverHello { local_port: 0 }).header().len() + 2 + 32 {
            let local_port = u16::from_be_bytes([msg[msg.len() - 34], msg[msg.len() - 33]]);
            let sha = sha2::Sha256::digest(&msg[..msg.len() - 32]);
            if msg.ends_with(&sha[..32]) {
                Some(DiscoveryMessage::DiscoverHello { local_port })
            } else {
                None
            }
        } else {
            None
        }
    }
    fn gen_message(&self) -> Vec<u8> {
        let header = self.header();
        let mut message = match self {
            DiscoveryMessage::Discovery => header.to_vec(),
            DiscoveryMessage::DiscoverHello { local_port } => {
                let mut hello_msg = header.to_vec();
                hello_msg.extend_from_slice(local_port.to_be_bytes().as_ref());
                hello_msg
            }
        };

        let sha = sha2::Sha256::digest(&message);
        message.extend_from_slice(&sha[..32]);
        message
    }
}


pub enum PollResult {
    Nothing,
    DiscoveredClient {
        addr: SocketAddrV4,
    }
}