use std::borrow::Cow;
use std::iter::once;
use std::net::IpAddr;
use std::ops::Range;

#[derive(Clone, Debug)]
pub struct MulticastDiscoveryConfig {
    pub multicast_group_ip: std::net::Ipv4Addr,
    pub multicast_port: u16,
    pub multicast_backup_ports: Vec<u16>,
    pub service_name: Cow<'static, str>,
    pub central_discovery_addr: Option<IpAddr>,
    
    pub enable_announce: bool
}

impl MulticastDiscoveryConfig {
    pub fn new(
        multicast_group_ip: std::net::Ipv4Addr,
        service_name: &'static str,
    ) -> Self {
        Self {
            multicast_group_ip,
            multicast_port: 37337,
            multicast_backup_ports: (61345..61347).collect(),
            service_name: Cow::Borrowed(service_name),
            central_discovery_addr: None,
            enable_announce: true,
        }
    }
    
    pub fn with_multicast_port(mut self, multicast_port: u16) -> Self {
        self.multicast_port = multicast_port;
        self
    }
    
    pub fn with_backup_ports(mut self, backup_ports: Range<u16>) -> Self {
        self.multicast_backup_ports = backup_ports.collect();
        self
    }
    
    pub fn iter_ports(&self) -> impl Iterator<Item = u16> + '_ {
        once(self.multicast_port).chain(self.multicast_backup_ports.iter().copied())
    }
    
    pub fn with_disabled_announce(mut self) -> Self {
        self.enable_announce = false;
        self
    }
}