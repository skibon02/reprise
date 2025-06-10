mod certs;
pub mod config;
pub mod multicast;

use std::net::Ipv4Addr;
use std::{io, thread};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::thread::yield_now;
use std::time::Duration;
use log::info;
use quinn::{ClientConfig, Endpoint, Incoming, VarInt};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::sync::{mpsc, watch};
use tokio::sync::watch::Sender;
use crate::config::MulticastDiscoveryConfig;
use crate::multicast::{MulticastDiscoverySocket, PollResult};
use quinn::rustls;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

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
        let (new_client_tx, mut new_client_rx) = mpsc::unbounded_channel();
        // handle multicast discovery in a separate thread
        let jh = thread::Builder::new().name("[Reprise accept]".to_string()).spawn(move || {
            info!("Multicast discovery running! discover_id: {:x}, port: {:?}", multicast_socket.discover_id(), multicast_socket.running_port());

            let mut discovered = BTreeSet::new();
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
                        if !discovered.contains(&addr) {
                            new_client_tx.send(addr).unwrap();
                        }
                        discovered.insert(addr);
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

        let mut endpoint_c1 = endpoint.clone();
        endpoint_c1.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new())
                .with_no_client_auth(),
        )?)));

        // Connection to remote
        tokio::spawn(async move {
            while let Some(addr) = new_client_rx.recv().await {
                info!("Trying to connect to {}", addr);
                let con = endpoint_c1.connect(addr.into(), "localhost").unwrap().await.unwrap();
                let id: Box<Vec<CertificateDer>> = con.peer_identity().unwrap().downcast().unwrap();
                info!("Connected! Remote id: {:?}", id);


                let (mut tx, mut rx) = con.open_bi().await.unwrap();
                info!("Sending hello to the remote...");
                tx.write_all(b"heya!").await.unwrap();

                let mut buf = [0u8; 100];
                if let Some(resp) = rx.read(&mut buf).await.unwrap() {
                    let packet = &buf[..resp];
                    info!("Got response: {:?}", String::from_utf8_lossy(packet));
                    con.close(VarInt::from_u32(0), b"bye-bye ^-^")
                }
            }
        });

        let accept_client = async |conn: Incoming, ep: Endpoint| -> Result<(), io::Error>{
            let con = conn.await?;
            let (mut tx, mut rx) = con.accept_bi().await?;
            info!("Connection accepted from {}", con.remote_address());
            // let id: Box<Vec<CertificateDer>> = con.peer_identity().unwrap().downcast().unwrap();
            // info!("Remote id: {:?}", id);
            let mut buf = [0u8; 100];
            if let Some(len) = rx.read(&mut buf).await? {
                if len < 90 {
                    let packet = &buf[..len];
                    info!("Received packet: {:?}", String::from_utf8_lossy(packet));
                    buf[len..len+6].copy_from_slice(b"-reply");
                    tx.write_all(&buf[..len+6]).await?;
                    info!("write_all finished")
                }
            }
            ep.wait_idle().await;
            con.close(VarInt::from_u32(0), b"bye-bye ^-^");
            Ok(())
        };
        // handle incoming connections in a separate task
        let endpoint_connection = endpoint.clone();
        tokio::spawn(async move {
            while let Some(conn) = endpoint_connection.accept().await {
                info!("New connection from {}", conn.remote_address());
                tokio::task::spawn(accept_client(conn, endpoint_connection.clone()));
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

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}