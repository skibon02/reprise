use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use anyhow::bail;
use if_addrs::get_if_addrs;
use log::{info, trace, warn};
use multicast_socket::{all_ipv4_interfaces, Interface, Message, MulticastOptions, MulticastSocket};
use sha2::Digest;
use tokio::time::Instant;
use crate::config::MulticastDiscoveryConfig;

const SEND_DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
const SEND_DISCOVERY_INTERVAL_BACKUP: Duration = Duration::from_secs(10);

pub struct MulticastDiscoverySocket {
    socket: MulticastSocket,
    local_port: u16,
    cfg: MulticastDiscoveryConfig,
    multicast_own_port: u16,
    discover_id: u32,

    send_discovery_tm: Option<Instant>,
    send_discovery_other_ports_tm: Option<Instant>,
}

impl MulticastDiscoverySocket {
    pub fn new(cfg: &MulticastDiscoveryConfig, local_port: u16) -> anyhow::Result<Self> {
        let mut is_primary = true;
        // Try primary and backup ports
        for port in cfg.iter_ports() {
            let options = MulticastOptions {
                read_timeout: Some(Duration::from_millis(10)),
                reuse_addr: false,
                ..Default::default()
            };

            match MulticastSocket::with_options(
                SocketAddrV4::new(cfg.multicast_group_ip, port),
                all_ipv4_interfaces()?,
                options
            ) {
                Ok(socket) => {
                    if !is_primary {
                        warn!("Using backup multicast port {} for discovery", port);
                    }
                    else {
                        info!("Using primary multicast port {} for discovery", port);
                    }
                    return Ok(Self {
                        socket,
                        local_port,
                        cfg: cfg.clone(),
                        multicast_own_port: port,
                        discover_id: rand::random_range(0..u32::MAX),

                        send_discovery_tm: None,
                        send_discovery_other_ports_tm: None,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                    is_primary = false;
                    continue
                },
                Err(e) => {
                    bail!("Failed to create multicast socket on port {}: {}", port, e);
                }
            }
        }

        bail!("Failed to create multicast socket on any of the configured ports: {:?}", cfg);
    }


    pub fn poll(&mut self) -> PollResult {
        self.try_poll().unwrap_or(PollResult::Nothing)
    }
    fn try_poll(&mut self) -> Option<PollResult> {
        // 1. Announce on current multicast port
        if self.send_discovery_tm.is_none_or(|tm| Instant::now() > tm + SEND_DISCOVERY_INTERVAL) {
            self.send_discovery_tm = Some(Instant::now());
            
            let msg = DiscoveryMessage::Announce {local_port: self.local_port, discover_id: self.discover_id}.gen_message();
            for interface in all_interfaces() {
                // send discovery message to own port
                if let Err(e) = self.socket.send(&msg, &Interface::Ip(interface)) {
                    warn!("Failed to send discovery message on interface {}: {}", interface, e);
                } else {
                    trace!("Sent discovery message on interface {}", interface);
                }
            }
        }
        
        // 2. Announce on other multicast ports
        if self.send_discovery_other_ports_tm.is_none_or(|tm| Instant::now() > tm + SEND_DISCOVERY_INTERVAL_BACKUP) {
            self.send_discovery_other_ports_tm = Some(Instant::now());

            let msg = DiscoveryMessage::Announce {local_port: self.local_port, discover_id: self.discover_id}.gen_message();
            for port in self.cfg.iter_ports() {
                if port == self.multicast_own_port {
                    continue; // skip own port
                }
                
                for interface in all_interfaces() {
                    // send discovery message to own port
                    if let Err(e) = self.socket.send_to_port(&msg, &Interface::Ip(interface), port) {
                        warn!("Failed to send discovery message on interface {}: {}", interface, e);
                    } else {
                        trace!("Sent discovery message on interface {}", interface);
                    }
                }
            }
        }

        // 3. Handle incoming messages
        if let Ok(Message {
                data,
                origin_address,
                interface
             }) = self.socket.receive() {

            // Shut up messages from ourselves on all interfaces
            if all_interfaces().contains(&origin_address.ip()) && origin_address.port() == self.multicast_own_port  {
                return None;
            }


            match DiscoveryMessage::try_parse(&data) {
                Some(DiscoveryMessage::Discovery) => {
                    // info!("Received discovery message from {}", origin_address);
                    // let interface_ip = match interface {
                    //     Interface::Ip(ip) => Some(ip),
                    //     Interface::Index(i) => {
                    //         get_ip_from_ifindex(i)
                    //     }
                    //     _ => None
                    // };

                    None
                }
                Some(DiscoveryMessage::Announce { local_port, discover_id }) => {
                    
                    Some(PollResult::DiscoveredClient {
                        addr: SocketAddrV4::new(
                            *origin_address.ip(),
                            local_port,
                        ),
                        discover_id,
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
    Announce {
        local_port: u16,
        discover_id: u32,
    }
}

impl DiscoveryMessage {
    fn header(&self) -> &'static [u8] {
        match self {
            DiscoveryMessage::Discovery => b"discovery",
            DiscoveryMessage::Announce { .. } => b"announce",
        }
    }
    fn try_parse(msg: &[u8]) -> Option<Self> {
        if msg.starts_with(DiscoveryMessage::Discovery.header())
            && msg.len() == DiscoveryMessage::Discovery.header().len() + 32
            && msg.ends_with(sha2::Sha256::digest(&msg[..msg.len() - 32]).as_ref()) {
            Some(DiscoveryMessage::Discovery)
        } else if msg.starts_with(DiscoveryMessage::Announce { local_port: 0, discover_id: 0 }.header())
            && msg.len() == (DiscoveryMessage::Announce { local_port: 0, discover_id: 0 }).header().len() + 2 + 4 + 32 {
            let local_port = u16::from_be_bytes([msg[msg.len() - 38], msg[msg.len() - 37]]);
            let discover_id = u32::from_be_bytes([
                msg[msg.len() - 36], msg[msg.len() - 35],
                msg[msg.len() - 34], msg[msg.len() - 33]
            ]);
            let sha = sha2::Sha256::digest(&msg[..msg.len() - 32]);
            if msg.ends_with(&sha[..32]) {
                Some(DiscoveryMessage::Announce { local_port, discover_id })
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
            DiscoveryMessage::Announce { local_port, discover_id } => {
                let mut hello_msg = header.to_vec();
                hello_msg.extend_from_slice(local_port.to_be_bytes().as_ref());
                hello_msg.extend_from_slice(discover_id.to_be_bytes().as_ref());
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
        discover_id: u32,
    },
}