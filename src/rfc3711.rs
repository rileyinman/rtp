use crypto;
use handy_async::sync_io::{ReadExt, WriteExt};
use num::BigUint;
use splay_tree::SplaySet;
use std::borrow::Cow;
use std::io::Read;

use io::{ReadFrom, WriteTo};
use rfc3550;
use traits::{ReadPacket, RtcpPacket, RtpPacket};
use types::U48;
use {ErrorKind, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AesCm,
    AesF8,
    Null,
}
impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::AesCm
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationAlgorithm {
    HmacSha1,
}
impl Default for AuthenticationAlgorithm {
    fn default() -> Self {
        AuthenticationAlgorithm::HmacSha1
    }
}

pub trait Protocol: Sized {
    type PacketIndex: Sized + Ord + Into<u64> + Into<BigUint> + Copy;
    const ENC_KEY_LABEL: u8;
    const AUTH_KEY_LABEL: u8;
    const SALT_KEY_LABEL: u8;

    fn determine_packet_index(context: &Context<Self>, packet: &[u8]) -> Result<Self::PacketIndex>;
    fn get_authenticated_bytes<'a>(
        context: &Context<Self>,
        auth_portion: &'a [u8],
    ) -> Result<Cow<'a, [u8]>>;
    fn decrypt(context: &Context<Self>, packet: &[u8], index: Self::PacketIndex)
        -> Result<Vec<u8>>;
    fn update_highest_recv_index(context: &mut Context<Self>, index: Self::PacketIndex);
}

// TODO maybe use type marker to ensure one context is only ever used for either sending OR receiving
// https://tools.ietf.org/html/rfc3711#section-3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context<P: Protocol> {
    // TODO support re-keying
    // TODO support mki
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
    // Since actual kdr is a power of two, this only stores the power (+1).
    // i.e. actual kdr is 2^(key_derivation_rate-1) (or 0 in case of 0)
    pub key_derivation_rate: u8,
    pub encryption: EncryptionAlgorithm,
    pub authentication: AuthenticationAlgorithm,
    pub replay_list: SplaySet<P::PacketIndex>,
    pub session_encr_key: Vec<u8>,
    pub session_salt_key: Vec<u8>,
    pub session_auth_key: Vec<u8>,
    pub auth_tag_len: usize,
    pub protocol_specific: P,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srtp {
    pub rollover_counter: u32,
    pub highest_recv_seq_num: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srtcp {}

impl Context<Srtp> {
    pub fn new_srtp(master_key: &[u8], master_salt: &[u8]) -> Self {
        Context::new(
            master_key,
            master_salt,
            Srtp {
                rollover_counter: 0,
                highest_recv_seq_num: 0,
            },
        )
    }
}

impl Context<Srtcp> {
    pub fn new_srtcp(master_key: &[u8], master_salt: &[u8]) -> Self {
        Context::new(master_key, master_salt, Srtcp {})
    }
}

impl Srtp {
    fn parse_seq_num(packet: &[u8]) -> Result<u16> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        Ok(header.seq_num)
    }

    // Estimate packet index from packet sequence number, highest received
    // sequence number and current rollover_counter, i.e. determining the most
    // likely (minimizing index offset) ROC for the given sequence number.
    // As per https://tools.ietf.org/html/rfc3711#section-3.3.1
    fn estimate_packet_index(context: &Context<Self>, seq_num: u16) -> U48 {
        let Srtp {
            highest_recv_seq_num,
            rollover_counter,
        } = context.protocol_specific;
        let mid_seq_num = 1 << 15;
        let probable_roc = if highest_recv_seq_num < mid_seq_num {
            if highest_recv_seq_num + mid_seq_num < seq_num {
                rollover_counter.wrapping_sub(1)
            } else {
                rollover_counter
            }
        } else {
            if highest_recv_seq_num - mid_seq_num > seq_num {
                rollover_counter.wrapping_add(1)
            } else {
                rollover_counter
            }
        };
        (U48::from(probable_roc) << 16) + U48::from(seq_num)
    }
}

impl Protocol for Srtp {
    type PacketIndex = U48;
    const ENC_KEY_LABEL: u8 = 0;
    const AUTH_KEY_LABEL: u8 = 1;
    const SALT_KEY_LABEL: u8 = 2;

    fn determine_packet_index(context: &Context<Self>, packet: &[u8]) -> Result<Self::PacketIndex> {
        let seq_num = track_try!(Srtp::parse_seq_num(packet));
        Ok(Srtp::estimate_packet_index(context, seq_num))
    }

    fn get_authenticated_bytes<'a>(
        context: &Context<Self>,
        auth_portion: &'a [u8],
    ) -> Result<Cow<'a, [u8]>> {
        // For SRTP, the ROC is part of the authenticated bytes (but not in the actual packet)
        let roc = context.protocol_specific.rollover_counter;
        let mut auth_bytes = Vec::from(auth_portion);
        track_try!((&mut auth_bytes).write_u32be(roc));
        Ok(Cow::Owned(auth_bytes))
    }

    fn decrypt(
        context: &Context<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        let ssrc = header.ssrc;
        let encrypted_portion = &reader[0..reader.len() - context.auth_tag_len];

        let mut decrypted: Vec<u8> = Vec::new();
        track_try!(header.write_to(&mut decrypted));
        context.decrypt_portion(encrypted_portion, &mut decrypted, ssrc, index);
        Ok(decrypted)
    }

    fn update_highest_recv_index(context: &mut Context<Self>, index: Self::PacketIndex) {
        // https://tools.ietf.org/html/rfc3711#section-3.3.1
        let state = &mut context.protocol_specific;
        let rollover_counter = (index >> 16) as u32;
        let seq_num = index as u16;
        if rollover_counter == state.rollover_counter {
            if seq_num > state.highest_recv_seq_num {
                state.highest_recv_seq_num = seq_num;
            }
        } else if rollover_counter > state.rollover_counter {
            state.highest_recv_seq_num = seq_num;
            state.rollover_counter = rollover_counter;
        }
    }
}

impl Protocol for Srtcp {
    type PacketIndex = u32; // actually 31-bits
    const ENC_KEY_LABEL: u8 = 3;
    const AUTH_KEY_LABEL: u8 = 4;
    const SALT_KEY_LABEL: u8 = 5;

    fn determine_packet_index(context: &Context<Self>, packet: &[u8]) -> Result<Self::PacketIndex> {
        let reader = &mut &packet[packet.len() - context.auth_tag_len - 4..];
        let index = track_try!(reader.read_u32be());
        Ok(index & 0x7FFF_FFFF) // remove uppermost bit (aka. E-bit) which isn't part of the index
    }

    fn get_authenticated_bytes<'a>(
        _context: &Context<Self>,
        auth_portion: &'a [u8],
    ) -> Result<Cow<'a, [u8]>> {
        // For SRTCP the full packet index is already part of the packet
        Ok(Cow::Borrowed(auth_portion))
    }

    fn decrypt(
        context: &Context<Self>,
        packet: &[u8],
        index: Self::PacketIndex,
    ) -> Result<Vec<u8>> {
        let e_bit_reader = &mut &packet[packet.len() - context.auth_tag_len - 4..];
        let is_encrypted = track_try!(e_bit_reader.read_u32be()) & 0x8000_0000 != 0;
        if !is_encrypted {
            return Ok(Vec::from(
                &packet[..packet.len() - context.auth_tag_len - 4],
            ));
        }

        let reader = &mut &packet[..];
        let _ = track_try!(reader.read_u32be());
        let ssrc = track_try!(reader.read_u32be());
        let encrypted_portion = &reader[0..reader.len() - context.auth_tag_len - 4];

        let mut decrypted = Vec::from(&packet[..8]);
        context.decrypt_portion(encrypted_portion, &mut decrypted, ssrc, index);
        Ok(decrypted)
    }

    fn update_highest_recv_index(_context: &mut Context<Self>, _index: Self::PacketIndex) {
        // full packet inex is part of SRTCP packets, no need to keep track of it
    }
}

impl<P: Protocol> Context<P>
where
    u64: From<P::PacketIndex>,
{
    pub fn new(master_key: &[u8], master_salt: &[u8], protocol_specific: P) -> Self {
        Context {
            master_key: Vec::from(master_key),
            master_salt: Vec::from(master_salt),
            key_derivation_rate: 0,
            encryption: EncryptionAlgorithm::default(),
            authentication: AuthenticationAlgorithm::default(),
            replay_list: SplaySet::new(),
            session_encr_key: vec![0; 128 / 8],
            session_salt_key: vec![0; 112 / 8],
            session_auth_key: vec![0; 160 / 8],
            auth_tag_len: 80 / 8,
            protocol_specific,
        }
    }
    pub fn update_session_keys(&mut self, index: P::PacketIndex) {
        let index = if self.key_derivation_rate == 0 {
            0
        } else {
            u64::from(index) >> (self.key_derivation_rate - 1)
        };

        // TODO: only recalculate if index changed, probably also cache surrounding indices
        //       but make sure the initial updates happens

        let index = BigUint::from(index);

        let enc_key_id =
            BigUint::from_bytes_be(&[P::ENC_KEY_LABEL, 0, 0, 0, 0, 0, 0]) + index.clone();
        let auth_key_id =
            BigUint::from_bytes_be(&[P::AUTH_KEY_LABEL, 0, 0, 0, 0, 0, 0]) + index.clone();
        let salt_key_id =
            BigUint::from_bytes_be(&[P::SALT_KEY_LABEL, 0, 0, 0, 0, 0, 0]) + index.clone();
        let master_salt = BigUint::from_bytes_be(&self.master_salt);

        self.session_encr_key = prf_n(
            &self.master_key,
            enc_key_id ^ master_salt.clone(),
            self.session_encr_key.len(),
        );
        self.session_auth_key = prf_n(
            &self.master_key,
            auth_key_id ^ master_salt.clone(),
            self.session_auth_key.len(),
        );
        self.session_salt_key = prf_n(
            &self.master_key,
            salt_key_id ^ master_salt.clone(),
            self.session_salt_key.len(),
        );
    }
    pub fn authenticate(&self, packet: &[u8]) -> Result<()> {
        let auth_portion = &packet[..packet.len() - self.auth_tag_len];
        let auth_tag = &packet[packet.len() - self.auth_tag_len..];

        let auth_bytes = track_try!(P::get_authenticated_bytes(self, auth_portion));

        let mut expected_tag = hmac_hash_sha1(&self.session_auth_key, &auth_bytes);
        expected_tag.truncate(self.auth_tag_len);
        track_assert_eq!(auth_tag, &expected_tag[..], ErrorKind::Invalid);
        Ok(())
    }
    pub fn decrypt_portion(
        &self,
        encrypted: &[u8],
        decrypted: &mut Vec<u8>,
        ssrc: u32,
        index: P::PacketIndex,
    ) {
        let iv = BigUint::from_bytes_be(&self.session_salt_key) << 16;
        let iv = iv ^ (BigUint::from(ssrc) << 64);
        let iv = iv ^ (index.into() << 16);
        let iv = &iv.to_bytes_be()[0..self.session_encr_key.len()];

        let mut ctr =
            crypto::aes::ctr(crypto::aes::KeySize::KeySize128, &self.session_encr_key, iv);
        let block_size = self.session_encr_key.len();

        for block in encrypted.chunks(block_size) {
            let old_len = decrypted.len();
            decrypted.resize(old_len + block.len(), 0);
            ctr.process(block, &mut decrypted[old_len..]);
        }
    }
    pub fn decrypt(&mut self, packet: &[u8], index: P::PacketIndex) -> Result<Vec<u8>> {
        P::decrypt(self, packet, index)
    }

    // https://tools.ietf.org/html/rfc3711#section-3.3
    // https://tools.ietf.org/html/rfc3711#section-3.4
    pub fn process_incoming(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        // Step 1: determining the correct context (has already happened at this point)

        // Step 2: Determine index of the packet
        let index = track_try!(P::determine_packet_index(self, packet));

        // Step 3: Determine master key and salt
        // TODO: support re-keying
        // TODO: support MKI

        // Step 4: Determine session keys and salt
        self.update_session_keys(index);

        // Step 5: Replay protection and authentication
        // TODO: replay protection
        track_try!(self.authenticate(packet));

        // Step 6: Decryption
        let result = track_try!(self.decrypt(packet, index));

        // Step 7: Update ROC, highest sequence number and replay protection
        // TODO: replay protection
        P::update_highest_recv_index(self, index);

        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpPacketReader<T> {
    context: Context<Srtp>,
    inner: T,
}
impl<T> SrtpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtpPacket,
{
    pub fn new(context: Context<Srtp>, inner: T) -> Self {
        SrtpPacketReader {
            context: context,
            inner: inner,
        }
    }
}
impl<T> ReadPacket for SrtpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtpPacket,
{
    type Packet = T::Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet> {
        let packet_bytes = track_try!(reader.read_all_bytes());
        let decrypted_packet_bytes = track_try!(self.context.process_incoming(&packet_bytes));
        track_err!(self.inner.read_packet(&mut &decrypted_packet_bytes[..]))
    }

    fn supports_type(&self, ty: u8) -> bool {
        self.inner.supports_type(ty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtcpPacketReader<T> {
    context: Context<Srtcp>,
    inner: T,
}
impl<T> SrtcpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtcpPacket,
{
    pub fn new(context: Context<Srtcp>, inner: T) -> Self {
        SrtcpPacketReader {
            context: context,
            inner: inner,
        }
    }
}
impl<T> ReadPacket for SrtcpPacketReader<T>
where
    T: ReadPacket,
    T::Packet: RtcpPacket,
{
    type Packet = T::Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet> {
        let packet_bytes = track_try!(reader.read_all_bytes());
        let decrypted_packet_bytes = track_try!(self.context.process_incoming(&packet_bytes));
        track_err!(self.inner.read_packet(&mut &decrypted_packet_bytes[..]))
    }

    fn supports_type(&self, ty: u8) -> bool {
        self.inner.supports_type(ty)
    }
}

fn hmac_hash_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use crypto::mac::Mac;
    let mut hmac = crypto::hmac::Hmac::new(crypto::sha1::Sha1::new(), key);
    hmac.input(data);
    Vec::from(hmac.result().code())
}

fn prf_n(master_key: &[u8], x: BigUint, n: usize) -> Vec<u8> {
    // https://tools.ietf.org/html/rfc3711#section-4.1.1
    let mut output = Vec::new();
    let mut ctr = crypto::aes::ctr(
        crypto::aes::KeySize::KeySize128,
        master_key,
        &(x << 16).to_bytes_be(),
    );
    for i in 0.. {
        let old_len = output.len();
        let new_len = output.len() + 16;
        output.resize(new_len, 0);

        let mut input = [0; 16];
        (&mut input[8..]).write_u64be(i).unwrap();
        ctr.process(&input[..], &mut output[old_len..]);
        if output.len() >= n {
            break;
        }
    }
    output.truncate(n);
    output
}

#[cfg(test)]
mod test {
    use super::*;
    use rfc3550;
    use rfc4585;

    #[test]
    fn rtp_packet_index_estimation_works() {
        let mut context = Context::new_srtp(&[], &[]);
        let roc = 0u32;
        let roc_n1 = roc.wrapping_sub(1);
        let roc_p1 = roc.wrapping_add(1);
        context.protocol_specific.rollover_counter = roc;

        let i = |roc, seq_num| ((roc as u64) << 16) + seq_num as u64;
        let estimate = |ctx: &Context<Srtp>, seq_num| Srtp::estimate_packet_index(ctx, seq_num);

        context.protocol_specific.highest_recv_seq_num = 1000; // low highest_seq_num
        assert_eq!(estimate(&context, 1), i(roc, 1)); // lower but same roc
        assert_eq!(estimate(&context, 10001), i(roc, 10001)); // higher but same roc
        assert_eq!(estimate(&context, 60001), i(roc_n1, 60001)); // roc-1
        context.protocol_specific.highest_recv_seq_num = 60000; // high highest_seq_num
        assert_eq!(estimate(&context, 60001), i(roc, 60001)); // higher but same roc
        assert_eq!(estimate(&context, 30001), i(roc, 30001)); // lower but same roc
        assert_eq!(estimate(&context, 10001), i(roc_p1, 10001)); // roc+1
    }

    #[test]
    fn rtp_decryption_works() {
        let master_key = [
            211, 77, 116, 243, 125, 116, 231, 95, 59, 219, 79, 118, 241, 189, 244, 119,
        ];
        let master_salt = [
            127, 31, 227, 93, 120, 247, 126, 117, 231, 159, 123, 235, 95, 122,
        ];

        let packet = [
            128, 0, 3, 92, 222, 161, 6, 76, 26, 163, 115, 130, 222, 0, 143, 87, 0, 227, 123, 91,
            200, 238, 141, 220, 9, 191, 52, 111, 100, 62, 220, 158, 211, 79, 184, 199, 79, 182, 9,
            248, 170, 82, 125, 152, 143, 206, 8, 152, 80, 207, 27, 183, 141, 77, 33, 60, 101, 180,
            210, 146, 139, 170, 149, 13, 99, 75, 223, 156, 79, 71, 84, 119, 68, 236, 244, 163, 198,
            175, 219, 160, 255, 9, 82, 169, 64, 112, 106, 4, 0, 246, 39, 29, 88, 15, 62, 174, 21,
            253, 171, 198, 128, 61, 23, 43, 143, 255, 176, 125, 223, 23, 188, 90, 103, 139, 223,
            56, 162, 35, 27, 225, 117, 243, 138, 163, 35, 79, 221, 201, 149, 154, 203, 255, 2, 23,
            184, 184, 169, 32, 1, 138, 172, 60, 70, 240, 53, 11, 54, 81, 172, 214, 34, 136, 39,
            152, 17, 247, 126, 199, 200, 184, 70, 7, 52, 191, 129, 239, 86, 78, 172, 229, 178, 112,
            22, 125, 191, 164, 17, 193, 24, 152, 197, 146, 94, 74, 156, 171, 245, 239, 220, 205,
            145, 206,
        ];

        let context = Context::new_srtp(&master_key, &master_salt);
        let mut rtp_reader = SrtpPacketReader::new(context, rfc3550::RtpPacketReader);
        let packet = rtp_reader.read_packet(&mut &packet[..]).unwrap();

        let expected_prefix = [
            0xbe, 0x9c, 0x8c, 0x86, 0x81, 0x80, 0x81, 0x86, 0x8d, 0x9c, 0xfd, 0x1b, 0x0d, 0x05,
            0x01, 0x00, 0x01, 0x05, 0x0d, 0x1b, 0xff, 0x9b, 0x8d, 0x85, 0x81, 0x80, 0x81, 0x85,
            0x8d, 0x9b, 0xff, 0x1b,
        ];

        assert_eq!(
            &packet.payload[..expected_prefix.len()],
            &expected_prefix[..]
        );
    }

    #[test]
    fn rtcp_decryption_works() {
        let master_key = [
            254, 123, 44, 240, 174, 252, 53, 54, 2, 213, 123, 106, 85, 165, 5, 13,
        ];
        let master_salt = [
            77, 202, 202, 112, 81, 101, 219, 232, 143, 131, 160, 89, 15, 141,
        ];
        let packet = [
            128, 201, 0, 1, 194, 242, 138, 93, 67, 38, 193, 233, 60, 78, 188, 195, 230, 90, 19,
            196, 152, 235, 136, 164, 15, 177, 174, 217, 207, 115, 148, 223, 109, 112, 71, 245, 16,
            214, 216, 232, 87, 153, 5, 238, 72, 201, 223, 43, 69, 99, 54, 211, 118, 28, 227, 100,
            161, 216, 90, 203, 99, 167, 215, 130, 151, 16, 128, 138, 128, 0, 0, 1, 126, 39, 201,
            236, 161, 194, 6, 232, 194, 230,
        ];

        let context = Context::new_srtcp(&master_key, &master_salt);
        let mut rtcp_reader = SrtcpPacketReader::new(context, rfc4585::RtcpPacketReader);
        let packet = track_try_unwrap!(rtcp_reader.read_packet(&mut &packet[..]));
        println!("# {:?}", packet);
    }
}
