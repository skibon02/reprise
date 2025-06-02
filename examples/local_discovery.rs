use std::net::Ipv4Addr;
use std::time::Duration;
use log::info;
use reprise::config::MulticastDiscoveryConfig;
use reprise::Reprise;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    
    let cfg = MulticastDiscoveryConfig::new(Ipv4Addr::new(239, 37, 37, 41), "reprise-test");
    let reprise = Reprise::spawn_with_discovery(cfg).unwrap();
    info!("Reprise started with multicast discovery!");
    tokio::time::sleep(Duration::from_secs(20)).await;
}