// FIXME: the current SRTP implementation does not support the maximum_lifetime parameter

#[cfg(feature = "openssl")]
mod openssl;

#[cfg(feature = "tokio")]
mod tokio;

use std::collections::VecDeque;
use std::io;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::Mutex;

use rfc3711::{AuthenticationAlgorithm, Context, EncryptionAlgorithm, Srtcp, Srtp};
use types::Ssrc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpProtectionProfile {
    pub name: &'static str,
    pub cipher: EncryptionAlgorithm,
    pub cipher_key_length: u8,
    pub cipher_salt_length: u8,
    pub maximum_lifetime: u32,
    pub auth_function: AuthenticationAlgorithm,
    pub auth_key_length: u8,
    pub auth_salt_length: u8,
}

impl SrtpProtectionProfile {
    pub const AES128_CM_HMAC_SHA1_80: SrtpProtectionProfile = SrtpProtectionProfile {
        name: "SRTP_AES128_CM_SHA1_80",
        cipher: EncryptionAlgorithm::AesCm,
        cipher_key_length: 128,
        cipher_salt_length: 112,
        maximum_lifetime: 2 ^ 31,
        auth_function: AuthenticationAlgorithm::HmacSha1,
        auth_key_length: 160,
        auth_salt_length: 80,
    };
    // AES128_CM_HMAC_SHA1_32 is not supported due to recommendation in rfc3711#5.2
    // NULL_HMAC_SHA1_80 is not supported because the NULL cipher isn't implemented
    // NULL_HMAC_SHA1_32 is not supported due to recommendation in rfc3711#5.2 (and lack of NULL)

    pub const RECOMMENDED: &'static [&'static SrtpProtectionProfile] =
        &[&SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80];
    pub const SUPPORTED: &'static [&'static SrtpProtectionProfile] =
        &[&SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80];
}

pub enum DtlsHandshakeResult<Dtls, DtlsMidHandshake> {
    Failure(io::Error),
    WouldBlock(DtlsMidHandshake),
    Success(Dtls),
}

pub trait DtlsBuilder<S> {
    type Instance: Dtls<S>;
    type MidHandshake: DtlsMidHandshake<S, Instance = Self::Instance>;

    fn handshake(self, stream: S) -> DtlsHandshakeResult<Self::Instance, Self::MidHandshake>
    where
        S: Read + Write;
}

pub trait DtlsMidHandshake<S>: Sized {
    type Instance: Dtls<S>;

    fn handshake(self) -> DtlsHandshakeResult<Self::Instance, Self>;
}

pub trait Dtls<S>: Read + Write {
    fn is_server_side(&self) -> bool;
    fn export_key(&mut self, exporter_label: &str, length: usize) -> Vec<u8>;
}

pub struct DtlsSrtpMuxer<S> {
    inner: S,
    dtls_buf: VecDeque<Vec<u8>>,
    srtp_buf: VecDeque<Vec<u8>>,
}

impl<S: Read + Write> DtlsSrtpMuxer<S> {
    fn new(inner: S) -> Self {
        DtlsSrtpMuxer {
            inner,
            dtls_buf: VecDeque::new(),
            srtp_buf: VecDeque::new(),
        }
    }
}

impl<S> DtlsSrtpMuxer<S> {
    fn into_parts(self) -> (DtlsSrtpMuxerPart<S>, DtlsSrtpMuxerPart<S>) {
        let muxer = Arc::new(Mutex::new(self));
        let dtls = DtlsSrtpMuxerPart {
            muxer: muxer.clone(),
            srtp: false,
        };
        let srtp = DtlsSrtpMuxerPart { muxer, srtp: true };
        (dtls, srtp)
    }
}

impl<S: Read> DtlsSrtpMuxer<S> {
    fn read(&mut self, want_srtp: bool, dst_buf: &mut [u8]) -> io::Result<usize> {
        {
            let want_buf = if want_srtp {
                &mut self.srtp_buf
            } else {
                &mut self.dtls_buf
            };
            if let Some(buf) = want_buf.pop_front() {
                return (&buf[..]).read(dst_buf);
            }
        }

        let mut buf = [0u8; 2048];
        let len = self.inner.read(&mut buf)?;
        if len == 0 {
            return Ok(0);
        }
        let mut buf = &buf[..len];
        // Demux SRTP and DTLS as per https://tools.ietf.org/html/rfc5764#section-5.1.2
        let is_srtp = buf[0] >= 128 && buf[0] <= 191;
        if is_srtp == want_srtp {
            buf.read(dst_buf)
        } else {
            if is_srtp {
                &mut self.srtp_buf
            } else {
                &mut self.dtls_buf
            }
            .push_back(buf.to_vec());
            // We have to make sure we're not waiting for, e.g., a srtp packet when
            // we just got a dtls packet and the remote is waiting on a reply to it.
            // So, to prevent this kind of deadlock, we abort the current read-path
            // by pretending that we're doing non-blocking io (even if we aren't)
            // to get back to where we can enter the other (in the example: the dtls)
            // read-path and process the packet we just read.
            Err(io::Error::new(io::ErrorKind::WouldBlock, ""))
        }
    }
}

pub struct DtlsSrtpMuxerPart<S> {
    muxer: Arc<Mutex<DtlsSrtpMuxer<S>>>,
    srtp: bool,
}

impl<S> Read for DtlsSrtpMuxerPart<S>
where
    S: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.muxer.lock().unwrap().read(self.srtp, buf)
    }
}

impl<S> Write for DtlsSrtpMuxerPart<S>
where
    S: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.muxer.lock().unwrap().inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.muxer.lock().unwrap().inner.flush()
    }
}

pub enum DtlsSrtpHandshakeResult<S: Read + Write, D: DtlsBuilder<DtlsSrtpMuxerPart<S>>> {
    Success(DtlsSrtp<S, D>),
    WouldBlock(DtlsSrtpMidHandshake<S, D>),
    Failure(io::Error),
}

pub struct DtlsSrtpMidHandshake<S: Read + Write, D: DtlsBuilder<DtlsSrtpMuxerPart<S>>> {
    stream: DtlsSrtpMuxerPart<S>,
    dtls: D::MidHandshake,
}

pub struct DtlsSrtp<S: Read + Write, D: DtlsBuilder<DtlsSrtpMuxerPart<S>>> {
    stream: DtlsSrtpMuxerPart<S>,
    dtls: D::Instance,
    srtp_read_context: Context<Srtp>,
    srtcp_read_context: Context<Srtcp>,
    srtp_write_context: Context<Srtp>,
    srtcp_write_context: Context<Srtcp>,
}

impl<S, D> DtlsSrtpMidHandshake<S, D>
where
    S: Read + Write + Sized,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    pub fn handshake(mut self) -> DtlsSrtpHandshakeResult<S, D> {
        match self.dtls.handshake() {
            DtlsHandshakeResult::Success(dtls) => {
                DtlsSrtpHandshakeResult::Success(DtlsSrtp::new(self.stream, dtls))
            }
            DtlsHandshakeResult::WouldBlock(dtls) => {
                self.dtls = dtls;
                DtlsSrtpHandshakeResult::WouldBlock(self)
            }
            DtlsHandshakeResult::Failure(err) => DtlsSrtpHandshakeResult::Failure(err),
        }
    }
}

impl<S, D> DtlsSrtp<S, D>
where
    S: Read + Write,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    pub fn handshake(stream: S, dtls_builder: D) -> DtlsSrtpHandshakeResult<S, D> {
        let (stream_dtls, stream_srtp) = DtlsSrtpMuxer::new(stream).into_parts();
        match dtls_builder.handshake(stream_dtls) {
            DtlsHandshakeResult::Success(dtls) => {
                DtlsSrtpHandshakeResult::Success(DtlsSrtp::new(stream_srtp, dtls))
            }
            DtlsHandshakeResult::WouldBlock(dtls) => {
                DtlsSrtpHandshakeResult::WouldBlock(DtlsSrtpMidHandshake {
                    stream: stream_srtp,
                    dtls,
                })
            }
            DtlsHandshakeResult::Failure(err) => DtlsSrtpHandshakeResult::Failure(err),
        }
    }

    fn new(stream: DtlsSrtpMuxerPart<S>, mut dtls: D::Instance) -> Self {
        const EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";
        const KEY_LEN: usize = 16;
        const SALT_LEN: usize = 14;
        const EXPORT_LEN: usize = (KEY_LEN + SALT_LEN) * 2;

        let key_material = dtls.export_key(EXPORTER_LABEL, EXPORT_LEN);
        let client_material = (
            &(&key_material[0..])[..KEY_LEN],
            &(&key_material[KEY_LEN * 2..])[..SALT_LEN],
        );
        let server_material = (
            &(&key_material[KEY_LEN..])[..KEY_LEN],
            &(&key_material[KEY_LEN * 2 + SALT_LEN..])[..SALT_LEN],
        );
        let (read_material, write_material) = if dtls.is_server_side() {
            (client_material, server_material)
        } else {
            (server_material, client_material)
        };
        let (read_key, read_salt) = read_material;
        let (write_key, write_salt) = write_material;
        DtlsSrtp {
            stream,
            dtls,
            srtp_read_context: Context::new(&read_key, &read_salt),
            srtcp_read_context: Context::new(&read_key, &read_salt),
            srtp_write_context: Context::new(&write_key, &write_salt),
            srtcp_write_context: Context::new(&write_key, &write_salt),
        }
    }

    pub fn add_incoming_ssrc(&mut self, ssrc: Ssrc) {
        self.srtp_read_context.add_ssrc(ssrc);
        self.srtcp_read_context.add_ssrc(ssrc);
    }

    pub fn add_incoming_unknown_ssrcs(&mut self, count: usize) {
        self.srtp_read_context.add_unknown_ssrcs(count);
        self.srtcp_read_context.add_unknown_ssrcs(count);
    }

    pub fn add_outgoing_ssrc(&mut self, ssrc: Ssrc) {
        self.srtp_write_context.add_ssrc(ssrc);
        self.srtcp_write_context.add_ssrc(ssrc);
    }

    pub fn add_outgoing_unknown_ssrcs(&mut self, count: usize) {
        self.srtp_write_context.add_unknown_ssrcs(count);
        self.srtcp_write_context.add_unknown_ssrcs(count);
    }

    fn process_incoming_srtp_packet(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        // Demux SRTP and SRTCP packets as per https://tools.ietf.org/html/rfc5761#section-4
        let payload_type = buf[1] & 0x7f;
        if 64 <= payload_type && payload_type <= 95 {
            self.srtcp_read_context.process_incoming(buf).ok()
        } else {
            self.srtp_read_context.process_incoming(buf).ok()
        }
    }

    fn process_outgoing_srtp_packet(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        // Demux SRTP and SRTCP packets as per https://tools.ietf.org/html/rfc5761#section-4
        let payload_type = buf[1] & 0x7f;
        if 64 <= payload_type && payload_type <= 95 {
            self.srtcp_write_context.process_outgoing(buf).ok()
        } else {
            self.srtp_write_context.process_outgoing(buf).ok()
        }
    }
}

impl<S, D> Read for DtlsSrtp<S, D>
where
    S: Read + Write,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Check if we have an SRTP packet in the queue
            if self.stream.muxer.lock().unwrap().srtp_buf.is_empty() {
                // if we don't, then poll the dtls layer which will read from the
                // underlying packet stream and produce either dtls data or fill
                // the SRTP packet queue or fail due to WouldBlock
                /* FIXME polling dtls eventually errs with a read timeout, for some reason
                 *       it does indeed send repeated "Change Cipher Spec" and "Encrypted Handshake
                 *       Message" as if its expecting a response to those but none is sent by FF?
                match self.dtls.read(buf) {
                    Ok(len) => return Ok(len),
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        // Either we're using non-blocking io and there's no more data
                        // available, or we received an SRTP packet which needs handling
                    }
                    err => return err,
                };
                */
            }

            // Read and handle the next SRTP packet from the queue
            let mut raw_buf = [0u8; 2048];
            let len = self.stream.read(&mut raw_buf)?;
            if len == 0 {
                return Ok(0);
            }
            let raw_buf = &raw_buf[..len];
            return match self.process_incoming_srtp_packet(raw_buf) {
                Some(result) => (&result[..]).read(buf),
                None => {
                    // FIXME: check rfc for whether this should be dropped silently
                    continue; // packet failed to auth or decrypt, drop it and try the next one
                }
            };
        }
    }
}

impl<S, D> Write for DtlsSrtp<S, D>
where
    S: Read + Write,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(buf) = self.process_outgoing_srtp_packet(buf) {
            self.stream.write(&buf)
        } else {
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use rfc3711::test::{
        TEST_MASTER_KEY, TEST_MASTER_SALT, TEST_SRTCP_PACKET, TEST_SRTCP_SSRC, TEST_SRTP_PACKET,
        TEST_SRTP_SSRC,
    };

    struct DummyDtlsBuilder;
    struct DummyDtls<S> {
        connected: bool,
        stream: S,
    }

    const DUMMY_DTLS_NOOP: &[u8] = &[20, 42];
    const DUMMY_DTLS_HELLO: &[u8] = &[62, 42];
    const DUMMY_DTLS_CONNECTED: &[u8] = &[63, 42];

    impl DummyDtlsBuilder {
        fn new() -> Self {
            DummyDtlsBuilder {}
        }
    }
    impl<S: Read + Write> DtlsBuilder<S> for DummyDtlsBuilder {
        type Instance = DummyDtls<S>;
        type MidHandshake = DummyDtls<S>;

        fn handshake(
            self,
            mut stream: S,
        ) -> DtlsHandshakeResult<Self::Instance, Self::MidHandshake> {
            stream.write(DUMMY_DTLS_HELLO).unwrap();
            DummyDtls {
                stream,
                connected: false,
            }
            .handshake()
        }
    }
    impl<S: Read + Write> DtlsMidHandshake<S> for DummyDtls<S> {
        type Instance = Self;
        fn handshake(mut self) -> DtlsHandshakeResult<Self::Instance, Self> {
            let result = self.read(&mut []).unwrap_err();
            if result.kind() == io::ErrorKind::WouldBlock {
                if self.connected {
                    DtlsHandshakeResult::Success(self)
                } else {
                    DtlsHandshakeResult::WouldBlock(self)
                }
            } else {
                DtlsHandshakeResult::Failure(result)
            }
        }
    }
    impl<S: Read + Write> Dtls<S> for DummyDtls<S> {
        fn is_server_side(&self) -> bool {
            true
        }

        fn export_key(&mut self, exporter_label: &str, length: usize) -> Vec<u8> {
            assert_eq!(exporter_label, "EXTRACTOR-dtls_srtp");
            let mut buf = Vec::new();
            buf.extend(TEST_MASTER_KEY);
            buf.extend(TEST_MASTER_KEY);
            let idx = buf.len() - 1;
            buf[idx] = 0;
            buf.extend(TEST_MASTER_SALT);
            buf.extend(TEST_MASTER_SALT);
            let idx = buf.len() - 1;
            buf[idx] = 0;
            assert_eq!(length, buf.len());
            buf
        }
    }

    impl<S: Read + Write> Read for DummyDtls<S> {
        fn read(&mut self, _dst: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut buf = [0u8; 2048];
                let len = self.stream.read(&mut buf)?;
                assert_eq!(len, 2);
                assert_eq!(buf[1], 42);
                match &buf[..len] {
                    DUMMY_DTLS_NOOP => {}
                    DUMMY_DTLS_HELLO => {
                        self.stream.write(DUMMY_DTLS_CONNECTED)?;
                    }
                    DUMMY_DTLS_CONNECTED => {
                        self.connected = true;
                    }
                    _ => panic!(),
                };
            }
        }
    }

    impl<S: Write> Write for DummyDtls<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.stream.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    type PacketBufArc = Arc<Mutex<VecDeque<Vec<u8>>>>;
    pub(crate) struct DummyTransport {
        read_buf: PacketBufArc,
        write_buf: PacketBufArc,
    }

    impl DummyTransport {
        pub fn new() -> (Self, Self) {
            let read_buf = Arc::new(Mutex::new(VecDeque::new()));
            let write_buf = Arc::new(Mutex::new(VecDeque::new()));
            (
                DummyTransport {
                    read_buf: read_buf.clone(),
                    write_buf: write_buf.clone(),
                },
                DummyTransport {
                    read_buf: write_buf.clone(),
                    write_buf: read_buf.clone(),
                },
            )
        }

        pub fn read_packet(&mut self) -> Option<Vec<u8>> {
            self.read_buf.lock().unwrap().pop_front()
        }
    }

    impl Read for DummyTransport {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.read_buf.lock().unwrap().pop_front() {
                None => Err(io::Error::new(io::ErrorKind::WouldBlock, "")),
                Some(elem) => (&mut &elem[..]).read(buf),
            }
        }
    }

    impl Write for DummyTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_buf.lock().unwrap().push_back(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    macro_rules! assert_wouldblock {
        ( $expr:expr ) => {
            let err = $expr.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        };
    }

    fn new_dtls_srtp() -> (DummyTransport, DtlsSrtp<DummyTransport, DummyDtlsBuilder>) {
        let (mut stream, dummy_stream) = DummyTransport::new();
        stream.write(DUMMY_DTLS_CONNECTED).unwrap();
        match DtlsSrtp::handshake(dummy_stream, DummyDtlsBuilder::new()) {
            DtlsSrtpHandshakeResult::Success(mut dtls_srtp) => {
                assert_eq!(&stream.read_packet().unwrap()[..], DUMMY_DTLS_HELLO);
                dtls_srtp.add_incoming_ssrc(TEST_SRTP_SSRC);
                dtls_srtp.add_incoming_ssrc(TEST_SRTCP_SSRC);
                dtls_srtp.add_outgoing_ssrc(TEST_SRTP_SSRC);
                dtls_srtp.add_outgoing_ssrc(TEST_SRTCP_SSRC);
                (stream, dtls_srtp)
            }
            _ => panic!("DTLS-SRTP handshake failed"),
        }
    }

    #[test]
    fn polls_dtls_layer_for_keys() {
        let (mut stream, dummy_stream) = DummyTransport::new();
        let handshake = DtlsSrtp::handshake(dummy_stream, DummyDtlsBuilder::new());
        let handshake = match handshake {
            DtlsSrtpHandshakeResult::WouldBlock(it) => it,
            _ => panic!(),
        };

        stream.write(TEST_SRTP_PACKET).unwrap(); // too early, should be discarded

        let handshake = match handshake.handshake() {
            DtlsSrtpHandshakeResult::WouldBlock(it) => it,
            _ => panic!(),
        };
        assert_eq!(&stream.read_packet().unwrap()[..], DUMMY_DTLS_HELLO);

        stream.write(DUMMY_DTLS_HELLO).unwrap();
        let handshake = match handshake.handshake() {
            DtlsSrtpHandshakeResult::WouldBlock(it) => it,
            _ => panic!(),
        };
        assert_eq!(&stream.read_packet().unwrap()[..], DUMMY_DTLS_CONNECTED);

        stream.write(DUMMY_DTLS_CONNECTED).unwrap();
        match handshake.handshake() {
            DtlsSrtpHandshakeResult::Success(_) => {}
            _ => panic!(),
        };
    }

    #[test]
    fn decryption_of_incoming_srtp_and_srtcp_works() {
        let mut buf = [0u8; 2048];
        let (mut stream, mut dtls_srtp) = new_dtls_srtp();

        stream.write(TEST_SRTP_PACKET).unwrap();
        stream.write(TEST_SRTCP_PACKET).unwrap();
        assert_eq!(dtls_srtp.read(&mut buf).unwrap(), 182); // srtp
        assert_eq!(dtls_srtp.read(&mut buf).unwrap(), 68); // srtcp
    }

    #[test]
    fn does_not_allow_replay_of_packets() {
        let mut buf = [0u8; 2048];
        let (mut stream, mut dtls_srtp) = new_dtls_srtp();

        stream.write(TEST_SRTP_PACKET).unwrap();
        stream.write(TEST_SRTP_PACKET).unwrap();
        stream.write(TEST_SRTP_PACKET).unwrap();
        assert_eq!(dtls_srtp.read(&mut buf).unwrap(), 182);
        assert_wouldblock!(dtls_srtp.read(&mut buf));

        stream.write(TEST_SRTCP_PACKET).unwrap();
        stream.write(TEST_SRTCP_PACKET).unwrap();
        stream.write(TEST_SRTCP_PACKET).unwrap();
        assert_eq!(dtls_srtp.read(&mut buf).unwrap(), 68);
        assert_wouldblock!(dtls_srtp.read(&mut buf));
    }
}
