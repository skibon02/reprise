use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;
use log::info;
use reprise::config::MulticastDiscoveryConfig;
use reprise::Reprise;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    
    let main_port = env::args().nth(1).unwrap_or("38338".to_string());
    
    let main_port = main_port.parse().unwrap_or(38338);
    let cfg = MulticastDiscoveryConfig::new(Ipv4Addr::new(239, 37, 37, 41), "reprise-test".into())
        .with_multicast_port(main_port)
        .with_backup_ports(main_port + 1_123..main_port + 1_125);
    let reprise = Reprise::new_node(cfg).unwrap();
    info!("Reprise started with multicast discovery!");
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        // reprise.discover();
    }
}