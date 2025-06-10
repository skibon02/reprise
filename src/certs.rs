use quinn::rustls;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

pub fn generate_self_signed_cert()
    -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), rcgen::Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    Ok((cert_der, key))
}