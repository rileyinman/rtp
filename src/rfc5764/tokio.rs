use std::io;
use tokio::prelude::{Async, AsyncRead, AsyncSink, AsyncWrite, Future, Sink, Stream};

use rfc5764::{DtlsBuilder, DtlsSrtp, DtlsSrtpHandshakeResult, DtlsSrtpMuxerPart};

impl<S, D> AsyncRead for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
}

impl<S, D> AsyncWrite for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    fn shutdown(&mut self) -> io::Result<Async<()>> {
        Ok(().into()) // FIXME
    }
}

impl<S, D> Future for DtlsSrtpHandshakeResult<S, D>
where
    S: AsyncRead + AsyncWrite,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
{
    type Item = DtlsSrtp<S, D>;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Self::Item>> {
        let mut owned = DtlsSrtpHandshakeResult::Failure(io::Error::new(
            io::ErrorKind::Other,
            "poll called after completion",
        ));
        std::mem::swap(&mut owned, self);
        match owned {
            DtlsSrtpHandshakeResult::Success(dtls_srtp) => Ok(Async::Ready(dtls_srtp)),
            DtlsSrtpHandshakeResult::WouldBlock(mid_handshake) => match mid_handshake.handshake() {
                DtlsSrtpHandshakeResult::Success(dtls_srtp) => Ok(Async::Ready(dtls_srtp)),
                mut new @ DtlsSrtpHandshakeResult::WouldBlock(_) => {
                    std::mem::swap(&mut new, self);
                    Ok(Async::NotReady)
                }
                DtlsSrtpHandshakeResult::Failure(err) => Err(err),
            },
            DtlsSrtpHandshakeResult::Failure(err) => Err(err),
        }
    }
}

impl<S, D> Stream for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
    DtlsSrtp<S, D>: AsyncRead + AsyncWrite,
{
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<Self::Item>>> {
        let mut buf = [0; 2048];
        Ok(match self.poll_read(&mut buf)? {
            Async::Ready(len) => {
                if len == 0 {
                    Async::Ready(None)
                } else {
                    Async::Ready(Some(buf[..len].to_vec()))
                }
            }
            Async::NotReady => Async::NotReady,
        })
    }
}

impl<S, D> Sink for DtlsSrtp<S, D>
where
    S: AsyncRead + AsyncWrite,
    D: DtlsBuilder<DtlsSrtpMuxerPart<S>>,
    DtlsSrtp<S, D>: AsyncRead + AsyncWrite,
{
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(&mut self, buf: Self::SinkItem) -> io::Result<AsyncSink<Self::SinkItem>> {
        Ok(match self.poll_write(&buf[..])? {
            Async::Ready(_) => AsyncSink::Ready,
            Async::NotReady => AsyncSink::NotReady(buf),
        })
    }

    fn poll_complete(&mut self) -> io::Result<Async<()>> {
        self.poll_flush()
    }
}
