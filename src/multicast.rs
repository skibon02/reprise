use std::io;
use std::iter::once;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use anyhow::bail;
use if_addrs::get_if_addrs;
use log::{debug, info, trace, warn};
use multicast_socket::{all_ipv4_interfaces, Interface, Message, MulticastOptions, MulticastSocket};
use sha2::Digest;
use tokio::time::Instant;
use crate::config::MulticastDiscoveryConfig;

const BG_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
const EXTENDED_ANNOUNCE_REQUEST_INTERVAL: Duration = Duration::from_secs(10);
const EXTENDED_ANNOUNCE_EFFECT_DUR: Duration = Duration::from_secs(30);

pub struct MulticastDiscoverySocket {
    socket: MulticastSocket,
    local_port: u16,
    cfg: MulticastDiscoveryConfig,
    multicast_own_port: u16,
    discover_id: u32,

    central_discovery_enabled: bool,
    announce_enabled: bool,
    extend_disc_request_tm: Option<Instant>,
    send_discovery_tm: Option<Instant>,
    send_discovery_other_ports_tm: Option<Instant>,
}

impl MulticastDiscoverySocket {
    // Create new socket for multicast discovery. Announcements are enabled by default
    pub fn new(cfg: &MulticastDiscoveryConfig, local_port: u16) -> anyhow::Result<Self> {
        let central_discovery_enabled = cfg.central_discovery_addr.is_some();
        let mut is_primary = true;
        // Try primary and backup ports
        let main_port = cfg.iter_ports().next().unwrap();
        for port in cfg.iter_ports().chain(once(0)) {
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
                    if is_primary {
                        debug!("Using primary multicast port {} for discovery", port);
                    }
                    else if port == 0 {
                        let failed_ports = cfg.iter_ports().filter(|p| *p != 0);
                        warn!("Unable to start on the main or backup ports ({:?})!", &failed_ports.collect::<Vec<_>>());
                        if !central_discovery_enabled {
                            warn!("You will be unable to discover other clients!");
                        }
                        else {
                            warn!("You will be able to discover clients only when your network is online!");
                        }
                    }
                    else {
                        warn!("Using backup multicast port {} for discovery (unable to start on main port {})", port, main_port);
                    }
                    return Ok(Self {
                        socket,
                        local_port,
                        cfg: cfg.clone(),
                        multicast_own_port: port,
                        discover_id: rand::random_range(0..u32::MAX),

                        central_discovery_enabled,
                        announce_enabled: cfg.enable_announce,
                        extend_disc_request_tm: None,
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
    
    pub fn discover_id(&self) -> u32 {
        self.discover_id
    }

    /// Setting this to `false` will disable both announcements and handling discovery packets
    pub fn set_announce_en(&mut self, en: bool) {
        self.announce_enabled = en;
    }


    /// Manually discover all clients on main or backup ports
    pub fn discover(&mut self) {
        info!("Multicast discovery: running manual discovery...");
        let msg = DiscoveryMessage::Discovery.gen_message();
        for interface in all_interfaces() {
            let ports = once(self.cfg.multicast_port);
            let ports = ports.chain(self.cfg.multicast_backup_ports.iter().copied());
            for port in ports {
                if let Err(e) = self.socket.send_to_port(&msg, &Interface::Ip(interface), port) {
                    warn!("Failed to send discovery message on interface {}: {}", interface, e);
                } else {
                    trace!("Sent discovery message to port {} on interface {}", port, interface);
                }
            }
        }
    }
    pub fn poll(&mut self) -> PollResult {
        self.try_poll().unwrap_or(PollResult::Nothing)
    }
    fn try_send_announce_packet(&mut self, disconnected: bool) {
        if self.announce_enabled {
            let is_extended_announcement = self.extend_disc_request_tm.is_some_and(|tm| tm.elapsed() < EXTENDED_ANNOUNCE_EFFECT_DUR);
            if self.send_discovery_tm.is_none_or(|tm| Instant::now() > tm + BG_ANNOUNCE_INTERVAL) {
                self.send_discovery_tm = Some(Instant::now());

                let msg = DiscoveryMessage::Announce {local_port: self.local_port, discover_id: self.discover_id, disconnected}.gen_message();
                for interface in all_interfaces() {
                    let ports = once(self.cfg.multicast_port);
                    let ports = if is_extended_announcement {
                        ports.chain(self.cfg.multicast_backup_ports.iter().copied())
                    }
                    else {
                        ports.chain([].iter().copied())
                    };
                    for port in ports {
                        if let Err(e) = self.socket.send_to_port(&msg, &Interface::Ip(interface), port) {
                            warn!("Failed to send discovery message on interface {}: {}", interface, e);
                        } else {
                            trace!("Sent discovery message to port {} on interface {}", port, interface);
                        }
                    }
                }
            }
        }
    }
    fn try_poll(&mut self) -> Option<PollResult> {
        // 1. Announce routine
        self.try_send_announce_packet(false);
            
        // 2. Handle incoming messages
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
                    if self.announce_enabled {
                        let announce = DiscoveryMessage::Announce {
                            disconnected: false,
                            discover_id: self.discover_id,
                            local_port: self.local_port,
                        }.gen_message();
                        if let Err(e) = self.socket.send_to(&announce, origin_address) {
                            warn!("Failed to answer to discovery packet: {:?}", e);
                        }
                        
                    }
                    None
                }
                Some(DiscoveryMessage::Announce { local_port, discover_id, disconnected}) => {
                    if disconnected {
                        Some(PollResult::DisconnectedClient {
                            addr: SocketAddrV4::new(
                                *origin_address.ip(),
                                local_port,
                            ),
                            discover_id
                        })
                    }
                    else {
                        Some(PollResult::DiscoveredClient {
                            addr: SocketAddrV4::new(
                                *origin_address.ip(),
                                local_port,
                            ),
                            discover_id,
                        })
                    }
                }
                Some(DiscoveryMessage::ExtendDiscovery) => {
                    self.extend_disc_request_tm = Some(Instant::now());
                    
                    None
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
impl Drop for MulticastDiscoverySocket {
    fn drop(&mut self) {
        // Announce disconnection
        self.try_send_announce_packet(true);
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
pub enum DiscoveryMessageType {
    Discovery,
    Announce,
    ExtendDiscovery,
}

impl DiscoveryMessageType {
    fn header(&self) -> &'static [u8] {
        match self {
            DiscoveryMessageType::Discovery => b"discovery",
            DiscoveryMessageType::Announce { .. } => b"announce",
            DiscoveryMessageType::ExtendDiscovery => b"extend-discovery",
        }
    }
}

#[derive(Copy, Clone)]
pub enum DiscoveryMessage {
    Discovery,
    Announce {
        local_port: u16,
        discover_id: u32,
        disconnected: bool,
    },
    ExtendDiscovery,
}

impl DiscoveryMessage {
    fn msg_type(&self) -> DiscoveryMessageType {
        match self {
            DiscoveryMessage::Discovery => DiscoveryMessageType::Discovery,
            DiscoveryMessage::Announce { .. } => DiscoveryMessageType::Announce,
            DiscoveryMessage::ExtendDiscovery => DiscoveryMessageType::ExtendDiscovery,
        }
    }
    fn try_parse(msg: &[u8]) -> Option<Self> {
        if msg.starts_with(DiscoveryMessageType::Discovery.header())
            && msg.len() == DiscoveryMessageType::Discovery.header().len() + 32
            && msg.ends_with(sha2::Sha256::digest(&msg[..msg.len() - 32]).as_ref()) {
            Some(DiscoveryMessage::Discovery)
        } else if msg.starts_with(DiscoveryMessageType::Announce.header())
            && msg.len() == DiscoveryMessageType::Announce.header().len() + 2 + 4 + 32 + 1 {
            let msg_body = &msg[DiscoveryMessageType::Announce.header().len()..];
            let local_port = u16::from_be_bytes(msg_body[0..2].try_into().unwrap());
            let discover_id = u32::from_be_bytes(msg_body[2..6].try_into().unwrap());
            let disconnected = msg_body[6] != 0;
            let sha = sha2::Sha256::digest(&msg[..msg.len() - 32]);
            if msg.ends_with(&sha[..32]) {
                Some(DiscoveryMessage::Announce { local_port, discover_id, disconnected })
            } else {
                None
            }
        } else if msg.starts_with(DiscoveryMessageType::ExtendDiscovery.header())
            && msg.len() == DiscoveryMessageType::ExtendDiscovery.header().len() + 32
            && msg.ends_with(sha2::Sha256::digest(&msg[..msg.len() - 32]).as_ref()) {
            Some(DiscoveryMessage::ExtendDiscovery)
        } else {
            None
        }
    }
    fn gen_message(&self) -> Vec<u8> {
        let header = self.msg_type().header();
        let mut message = match self {
            DiscoveryMessage::Discovery => header.to_vec(),
            DiscoveryMessage::Announce { local_port, discover_id, disconnected } => {
                let mut hello_msg = header.to_vec();
                hello_msg.extend_from_slice(local_port.to_be_bytes().as_ref());
                hello_msg.extend_from_slice(discover_id.to_be_bytes().as_ref());
                hello_msg.push(*disconnected as u8);
                hello_msg
            }
            DiscoveryMessage::ExtendDiscovery => header.to_vec(),
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
    DisconnectedClient {
        addr: SocketAddrV4,
        discover_id: u32
    }
}