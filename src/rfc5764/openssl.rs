use std::io;
use std::io::{Read, Write};

use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, SslAcceptorBuilder, SslConnectorBuilder, SslStream,
};

use rfc5764::{Dtls, DtlsBuilder, DtlsHandshakeResult, DtlsMidHandshake, SrtpProtectionProfile};

impl<S: Read + Write + Sync> DtlsBuilder<S> for SslConnectorBuilder {
    type Instance = SslStream<S>;
    type MidHandshake = MidHandshakeSslStream<S>;

    fn handshake(mut self, stream: S) -> DtlsHandshakeResult<Self::Instance, Self::MidHandshake>
    where
        S: Read + Write,
    {
        let profiles_str: String = SrtpProtectionProfile::RECOMMENDED
            .iter()
            .map(|profile| profile.name.to_string())
            .collect::<Vec<_>>()
            .join(":");
        self.set_tlsext_use_srtp(&profiles_str).unwrap();
        match self.build().connect("invalid", stream) {
            Ok(stream) => DtlsHandshakeResult::Success(stream),
            Err(HandshakeError::WouldBlock(mid_handshake)) => {
                DtlsHandshakeResult::WouldBlock(mid_handshake)
            }
            Err(HandshakeError::Failure(mid_handshake)) => DtlsHandshakeResult::Failure(
                io::Error::new(io::ErrorKind::Other, mid_handshake.into_error()),
            ),
            Err(HandshakeError::SetupFailure(err)) => {
                DtlsHandshakeResult::Failure(io::Error::new(io::ErrorKind::Other, err))
            }
        }
    }
}

impl<S: Read + Write + Sync> DtlsBuilder<S> for SslAcceptorBuilder {
    type Instance = SslStream<S>;
    type MidHandshake = MidHandshakeSslStream<S>;

    fn handshake(mut self, stream: S) -> DtlsHandshakeResult<Self::Instance, Self::MidHandshake>
    where
        S: Read + Write,
    {
        let profiles_str: String = SrtpProtectionProfile::RECOMMENDED
            .iter()
            .map(|profile| profile.name.to_string())
            .collect::<Vec<_>>()
            .join(":");
        self.set_tlsext_use_srtp(&profiles_str).unwrap();
        match self.build().accept(stream) {
            Ok(stream) => DtlsHandshakeResult::Success(stream),
            Err(HandshakeError::WouldBlock(mid_handshake)) => {
                DtlsHandshakeResult::WouldBlock(mid_handshake)
            }
            Err(HandshakeError::Failure(mid_handshake)) => DtlsHandshakeResult::Failure(
                io::Error::new(io::ErrorKind::Other, mid_handshake.into_error()),
            ),
            Err(HandshakeError::SetupFailure(err)) => {
                DtlsHandshakeResult::Failure(io::Error::new(io::ErrorKind::Other, err))
            }
        }
    }
}

impl<S: Read + Write + Sync> DtlsMidHandshake<S> for MidHandshakeSslStream<S> {
    type Instance = SslStream<S>;

    fn handshake(self) -> DtlsHandshakeResult<Self::Instance, Self> {
        match MidHandshakeSslStream::handshake(self) {
            Ok(stream) => DtlsHandshakeResult::Success(stream),
            Err(HandshakeError::WouldBlock(mid_handshake)) => {
                DtlsHandshakeResult::WouldBlock(mid_handshake)
            }
            Err(HandshakeError::Failure(mid_handshake)) => DtlsHandshakeResult::Failure(
                io::Error::new(io::ErrorKind::Other, mid_handshake.into_error()),
            ),
            Err(HandshakeError::SetupFailure(err)) => {
                DtlsHandshakeResult::Failure(io::Error::new(io::ErrorKind::Other, err))
            }
        }
    }
}

impl<S: Read + Write> Dtls<S> for SslStream<S> {
    fn is_server_side(&self) -> bool {
        self.ssl().is_server()
    }

    fn export_key(&mut self, exporter_label: &str, length: usize) -> Vec<u8> {
        let mut vec = vec![0; length];
        self.ssl()
            .export_keying_material(&mut vec, exporter_label, None)
            .unwrap();
        vec
    }
}

#[cfg(test)]
mod test {
    use rfc5764::test::DummyTransport;
    use rfc5764::{DtlsSrtp, DtlsSrtpHandshakeResult};

    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::X509;

    #[test]
    fn connect_and_establish_matching_key_material() {
        let (client_sock, server_sock) = DummyTransport::new();

        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut cert_builder = X509::builder().unwrap();
        cert_builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert_builder.set_pubkey(&key).unwrap();
        cert_builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = cert_builder.build();

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls()).unwrap();
        let mut connector = SslConnector::builder(SslMethod::dtls()).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_verify(SslVerifyMode::NONE);
        connector.set_verify(SslVerifyMode::NONE);
        let mut handshake_server = DtlsSrtp::handshake(server_sock, acceptor);
        let mut handshake_client = DtlsSrtp::handshake(client_sock, connector);

        loop {
            match (handshake_client, handshake_server) {
                (DtlsSrtpHandshakeResult::Failure(err), _) => {
                    panic!("Client error: {}", err);
                }
                (_, DtlsSrtpHandshakeResult::Failure(err)) => {
                    panic!("Server error: {}", err);
                }
                (
                    DtlsSrtpHandshakeResult::Success(client),
                    DtlsSrtpHandshakeResult::Success(server),
                ) => {
                    assert_eq!(
                        client.srtp_read_context.master_key,
                        server.srtp_write_context.master_key
                    );
                    assert_eq!(
                        client.srtp_read_context.master_salt,
                        server.srtp_write_context.master_salt
                    );
                    assert_eq!(
                        client.srtp_write_context.master_key,
                        server.srtp_read_context.master_key
                    );
                    assert_eq!(
                        client.srtp_write_context.master_salt,
                        server.srtp_read_context.master_salt
                    );
                    return;
                }
                (
                    DtlsSrtpHandshakeResult::WouldBlock(client),
                    DtlsSrtpHandshakeResult::WouldBlock(server),
                ) => {
                    handshake_client = client.handshake();
                    handshake_server = server.handshake();
                }
                (client, DtlsSrtpHandshakeResult::WouldBlock(server)) => {
                    handshake_client = client;
                    handshake_server = server.handshake();
                }
                (DtlsSrtpHandshakeResult::WouldBlock(client), server) => {
                    handshake_client = client.handshake();
                    handshake_server = server;
                }
            }
        }
    }
}
