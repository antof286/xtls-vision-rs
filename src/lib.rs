use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce, Tag};
use rand::Rng;
use rsa::rand_core::RngCore;
use rsa::Pkcs1v15Encrypt;
use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use rsa::{RsaPrivateKey, RsaPublicKey};

pub mod rsa {
    pub use rsa::*;
}

struct AesTlsTcpStream {
    aes: Aes256Gcm,
    receive_buffer: Box<[u8; 0x5000]>,
    receive_buffer_position: usize,
    receive_buffer_size: usize,
    receive_buffer_encrypted: bool,
    send_buffer: Box<[u8; 0x5000]>,
    send_buffer_position: usize,
    send_buffer_size: usize,
    stream: TcpStream
}

impl AesTlsTcpStream {
    pub(crate) fn new(aes: Aes256Gcm, stream: TcpStream) -> Self {
        Self {
            aes,
            receive_buffer: Box::new([0u8; 0x5000]),
            receive_buffer_position: 0,
            receive_buffer_size: 0,
            receive_buffer_encrypted: true,
            send_buffer: Box::new([0u8; 0x5000]),
            send_buffer_position: 0,
            send_buffer_size: 0,
            stream
        }
    }

    fn receive_buffer_left_to_fill(&self) -> io::Result<usize> {
        assert!(self.receive_buffer_encrypted);
        assert!(self.receive_buffer_size >= self.receive_buffer_position);

        if self.receive_buffer_size < 5 {
            return Ok(5 - self.receive_buffer_size);
        }
        let len = u16::from_be_bytes([self.receive_buffer[3], self.receive_buffer[4]]) as usize;
        if len <= 12 + 16 {
            return Err(io::ErrorKind::InvalidData.into());
        }

        assert!(self.receive_buffer_size <= len + 5);
        Ok((len + 5) - self.receive_buffer_size)
    }

    fn try_flush_send_buffer(&mut self) -> io::Result<()> {
        if self.send_buffer_size != 0 {
            let n = self.stream.try_write(&self.send_buffer[self.send_buffer_position..self.send_buffer_size])?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.send_buffer_position += n;
            if self.send_buffer_position != self.send_buffer_size {
                return Err(io::ErrorKind::WouldBlock.into())
            }
            self.send_buffer_position = 0;
            self.send_buffer_size = 0;
        }
        Ok(())
    }

    pub(crate) fn try_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        const MAX_TLS_RECORD_SIZE: usize = 0x4000;

        if buf.len() == 0 {
            return Ok(0);
        }

        if let Err(e) = self.try_flush_send_buffer() {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return Ok(0);
            }
            return Err(e);
        }
        assert!(self.send_buffer_size == 0 && self.send_buffer_position == 0);

        let buf = if buf.len() > MAX_TLS_RECORD_SIZE - 12 - 16 {
            &buf[..MAX_TLS_RECORD_SIZE - 12 - 16]
        } else {
            buf
        };

        self.send_buffer_size += 5 + 12;
        rsa::rand_core::OsRng.fill_bytes(&mut self.send_buffer[5..5 + 12]);
        self.send_buffer_size += 16;
        self.send_buffer_size += buf.len();
        self.send_buffer[5 + 12 + 16..5 + 12 + 16 + buf.len()].copy_from_slice(buf);
        self.send_buffer[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
        let (nonce, rest) = self.send_buffer[5..self.send_buffer_size].split_at_mut(12);
        let (tag_ref, body) = rest.split_at_mut(16);
        let tag = self.aes.encrypt_in_place_detached(
            &Nonce::from_slice(nonce),
            &[],
            body
        ).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        tag_ref.copy_from_slice(&tag);
        self.send_buffer[3..5].copy_from_slice(&((self.send_buffer_size - 5) as u16).to_be_bytes());

        let n = match self.stream.try_write(&self.send_buffer[..self.send_buffer_size]) {
            Ok(n) => n,
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(buf.len());
                }
                return Err(e);
            }
        };
        if n == 0 {
            return Ok(0);
        }
        self.send_buffer_position += n;
        if self.send_buffer_position == self.send_buffer_size {
            self.send_buffer_position = 0;
            self.send_buffer_size = 0;
        }
        Ok(buf.len())
    }

    pub(crate) fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.receive_buffer_encrypted {
            let receive_buffer =
                &self.receive_buffer[self.receive_buffer_position..self.receive_buffer_size];
            assert!(!receive_buffer.is_empty());

            let n = min(buf.len(), receive_buffer.len());
            buf[..n].copy_from_slice(&receive_buffer[..n]);
            self.receive_buffer_position += n;
            if self.receive_buffer_size == self.receive_buffer_position {
                self.receive_buffer_encrypted = true;
                self.receive_buffer_size = 0;
                self.receive_buffer_position = 0;
            }
            return Ok(n);
        }

        let left_to_fill = self.receive_buffer_left_to_fill()?;
        assert_ne!(left_to_fill, 0);

        let prev_receive_buffer_size = self.receive_buffer_size;
        self.receive_buffer_size += left_to_fill;
        let n = match self.stream.try_read(
            &mut self.receive_buffer[prev_receive_buffer_size..self.receive_buffer_size]
        ) {
            Ok(n) => n,
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.receive_buffer_size = prev_receive_buffer_size;
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                return Err(e);
            }
        };
        if n == 0 {
            return Ok(0);
        }
        self.receive_buffer_size = prev_receive_buffer_size + n;

        if self.receive_buffer_left_to_fill()? == 0 {
            let (nonce, rest) = self.receive_buffer[5..self.receive_buffer_size].split_at_mut(12);
            let (tag, body) = rest.split_at_mut(16);
            self.aes.decrypt_in_place_detached(
                &Nonce::from_slice(nonce),
                &[],
                body,
                Tag::from_slice(tag)
            ).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            self.receive_buffer_encrypted = false;
            self.receive_buffer_position += 5 + 12 + 16;
            return self.try_read(buf);
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    pub(crate) async fn writable(&self) -> io::Result<()> {
        self.stream.writable().await
    }

    pub(crate) async fn readable(&self) -> io::Result<()> {
        if !self.receive_buffer_encrypted {
            assert!(self.receive_buffer.len() > 5 + 12);
            return Ok(())
        }
        self.stream.readable().await
    }

    pub(crate) fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_write_ready(cx)
    }

    pub(crate) fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.receive_buffer_encrypted {
            return Poll::Ready(Ok(()))
        }
        self.stream.poll_read_ready(cx)
    }

    pub(crate) fn into_inner(self) -> TcpStream {
        assert_eq!(self.send_buffer_size, 0);
        assert_eq!(self.receive_buffer_size, 0);

        self.stream
    }
}

impl AsyncRead for AesTlsTcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            return match self.poll_read_ready(cx) {
                Poll::Ready(Ok(_)) => {
                    let b = buf.initialize_unfilled();
                    match self.try_read(b) {
                        Ok(n) => {
                            buf.advance(n);
                            Poll::Ready(Ok(()))
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                continue;
                            }
                            Poll::Ready(Err(e))
                        }
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending
            }
        }
    }
}

impl AsyncWrite for AesTlsTcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            return match self.poll_write_ready(cx) {
                Poll::Ready(Ok(_)) => {
                    match self.try_write(buf) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                continue;
                            }
                            Poll::Ready(Err(e))
                        }
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            return match self.try_flush_send_buffer() {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        match self.poll_write_ready(cx) {
                            Poll::Ready(Ok(_)) => {
                                continue;
                            }
                            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                            Poll::Pending => Poll::Pending,
                        }
                    } else {
                        Poll::Ready(Err(e))
                    }
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            return match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(_)) => {
                    Pin::new(&mut self.stream).poll_shutdown(cx)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum TlsAnalyzerEnd {
    Client,
    Server
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum TlsAnalyzerState {
    NoData,
    ClientHelloArrived,
    ApplicationDataArrived(TlsAnalyzerEnd),
    Done
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum TlsAnalyzerResult {
    NeedMoreData,
    IsTls(usize),
    NotTls
}
struct TlsAnalyzer {
    client_buffer: Vec<u8>,
    server_buffer: Vec<u8>,
    state: TlsAnalyzerState
}

impl TlsAnalyzer {
    pub fn new() -> Self {
        Self {
            client_buffer: Vec::with_capacity(u16::MAX as usize),
            server_buffer: Vec::with_capacity(u16::MAX as usize),
            state: TlsAnalyzerState::NoData,
        }
    }

    pub fn is_done(&self) -> bool {
        self.state == TlsAnalyzerState::Done
    }

    pub fn force_done(&mut self) {
        if self.state != TlsAnalyzerState::Done {
            self.state = TlsAnalyzerState::Done;
        } else {
            panic!("TlsAnalyzer::force_done called on terminated TlsAnalyzer")
        }
    }

    pub fn write_client(&mut self, buf: &[u8]) -> TlsAnalyzerResult {
        self.client_buffer.extend_from_slice(buf);
        match self.state {
            TlsAnalyzerState::NoData => {
                if self.client_buffer.len() < 5 {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                let version = u16::from_be_bytes([self.client_buffer[1], self.client_buffer[2]]);
                if self.client_buffer[0] == 0x16 && ([0x0301, 0x0303, 0x0304].contains(&version)) {
                    let len = u16::from_be_bytes([self.client_buffer[3], self.client_buffer[4]]) as usize;
                    if len > self.client_buffer.len() - 5 {
                        return TlsAnalyzerResult::NeedMoreData;
                    }

                    self.state = TlsAnalyzerState::ClientHelloArrived;
                    self.client_buffer.drain(..len + 5);
                    self.write_client(&[])
                } else {
                    self.state = TlsAnalyzerState::Done;
                    TlsAnalyzerResult::NotTls
                }
            }
            TlsAnalyzerState::ClientHelloArrived | TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Server) => {
                if self.client_buffer.len() < 5 {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                let version = u16::from_be_bytes([self.client_buffer[1], self.client_buffer[2]]);
                if ![0x0301, 0x0303, 0x0304].contains(&version) {
                    self.state = TlsAnalyzerState::Done;
                    return TlsAnalyzerResult::NotTls;
                }
                let len = u16::from_be_bytes([self.client_buffer[3], self.client_buffer[4]]) as usize;
                if len > self.client_buffer.len() {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                if self.client_buffer[0] == 0x17 {
                    if self.state == TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Server) {
                        self.state = TlsAnalyzerState::Done;
                        return TlsAnalyzerResult::IsTls(self.client_buffer.len() - len - 5);
                    }
                    self.state = TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Client);
                }
                self.client_buffer.drain(..len + 5);
                self.write_client(&[])
            }
            TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Client) => {
                if self.client_buffer.len() < 5 {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                let len = u16::from_be_bytes([self.client_buffer[3], self.client_buffer[4]]) as usize;
                if len > self.client_buffer.len() {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                self.client_buffer.drain(..len + 5);
                self.write_client(&[])
            }
            TlsAnalyzerState::Done => panic!("Tls analyzer used after it's done")
        }
    }

    pub fn write_server(&mut self, buf: &[u8]) -> TlsAnalyzerResult {
        self.server_buffer.extend_from_slice(buf);
        match self.state {
            TlsAnalyzerState::NoData => {
                TlsAnalyzerResult::NotTls
            }
            TlsAnalyzerState::ClientHelloArrived | TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Client) => {
                if self.server_buffer.len() < 5 {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                let version = u16::from_be_bytes([self.server_buffer[1], self.server_buffer[2]]);
                if ![0x0301, 0x0303, 0x0304].contains(&version) {
                    self.state = TlsAnalyzerState::Done;
                    return TlsAnalyzerResult::NotTls;
                }
                let len = u16::from_be_bytes([self.server_buffer[3], self.server_buffer[4]]) as usize;
                if len > self.server_buffer.len() {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                if self.server_buffer[0] == 0x17 {
                    if self.state == TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Client) {
                        self.state = TlsAnalyzerState::Done;
                        return TlsAnalyzerResult::IsTls(self.server_buffer.len() - len - 5);
                    }
                    self.state = TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Server);
                }
                self.server_buffer.drain(..len + 5);
                self.write_server(&[])
            }
            TlsAnalyzerState::ApplicationDataArrived(TlsAnalyzerEnd::Server) => {
                if self.server_buffer.len() < 5 {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                let len = u16::from_be_bytes([self.server_buffer[3], self.server_buffer[4]]) as usize;
                if len > self.server_buffer.len() {
                    return TlsAnalyzerResult::NeedMoreData;
                }
                self.server_buffer.drain(..len + 5);
                self.write_server(&[])
            }
            TlsAnalyzerState::Done => panic!("Tls analyzer used after it's done")
        }
    }
}

struct XTlsInnerStream {
    aes_stream: Option<AesTlsTcpStream>,
    tcp_stream: Option<TcpStream>
}

impl XTlsInnerStream {
    pub(crate) fn new(aes: Aes256Gcm, inner: TcpStream) -> Self {
        Self {
            aes_stream: Some(AesTlsTcpStream::new(aes, inner)),
            tcp_stream: None
        }
    }

    pub(crate) fn get_mut(&mut self) -> Result<&mut AesTlsTcpStream, &mut TcpStream> {
        if let Some(aes_stream) = self.aes_stream.as_mut() {
            return Ok(aes_stream);
        }
        if let Some(tcp_stream) = self.tcp_stream.as_mut() {
            return Err(tcp_stream);
        }
        panic!("Invalid state of XTlsInnerStream");
    }

    pub(crate) fn get(&self) -> Result<&AesTlsTcpStream, &TcpStream> {
        if let Some(aes_stream) = self.aes_stream.as_ref() {
            return Ok(aes_stream);
        }
        if let Some(tcp_stream) = self.tcp_stream.as_ref() {
            return Err(tcp_stream);
        }
        panic!("Invalid state of XTlsInnerStream");
    }

    pub(crate) fn get_aes_stream(&mut self) -> Option<&mut AesTlsTcpStream> {
        self.aes_stream.as_mut()
    }

    pub(crate) fn convert_to_tcp(&mut self) {
        let aes = self.aes_stream.take().unwrap();
        self.tcp_stream = Some(aes.into_inner());
    }
}

pub struct XTlsVisionStream {
    inner: XTlsInnerStream,
    analyzer: TlsAnalyzer,
    send_buffer: Box<[u8; 0x5000]>,
    send_buffer_position: usize,
    send_buffer_size: usize,
    should_convert_after_send_buffer: bool,
    is_client: bool,
    early_data: bool
}

impl XTlsVisionStream {
    fn make_tls_packet(payload_vectored: &[&[u8]]) -> Vec<u8> {
        let mut tls_packet: Vec<u8> = Vec::new();
        tls_packet.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x00]);
        let mut payload_len = 0;
        for payload in payload_vectored {
            tls_packet.extend_from_slice(payload);
            payload_len += payload.len();
        }
        if payload_len > u16::MAX as usize {
            panic!("Payload is too big");
        }
        tls_packet[3..5].copy_from_slice(&(payload_len as u16).to_be_bytes());
        tls_packet
    }

    async fn read_tls_packet<T: AsyncRead + Unpin>(
        stream: &mut T,
        buf: &mut [u8; u16::MAX as usize]
    ) -> io::Result<usize> {
        let mut tls_header = [0u8; 5];
        stream.read_exact(&mut tls_header).await?;
        let len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;

        stream.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }

    pub async fn negotiate_as_client(
        mut stream: TcpStream,
        rsa_public_key: RsaPublicKey
    ) -> io::Result<Self> {
        stream.set_nodelay(true)?;

        let mut rng = rsa::rand_core::OsRng;
        let mut aes_key = [0u8; 32];
        rng.fill_bytes(&mut aes_key);
        // The only error `encrypt` returns is "Message too long"
        // Obviously it is not
        let encrypted_key = rsa_public_key.encrypt(
            &mut rng,
            Pkcs1v15Encrypt,
            &aes_key
        ).unwrap();
        let random_padding_len = rng.gen_range(200usize..600usize);
        let mut random_padding = [0u8; 600];
        rng.fill_bytes(&mut random_padding[..random_padding_len]);
        let tls_packet = Self::make_tls_packet(
            &[
                &(encrypted_key.len() as u16).to_be_bytes(),
                &encrypted_key,
                &random_padding[..random_padding_len]
            ],
        );
        stream.write_all(&tls_packet).await?;

        Ok(Self {
            inner: XTlsInnerStream::new(
                Aes256Gcm::new(&Key::<Aes256Gcm>::from(aes_key)),
                stream
            ),
            analyzer: TlsAnalyzer::new(),
            is_client: true,
            send_buffer: Box::new([0u8; 0x5000]),
            send_buffer_position: 0,
            send_buffer_size: 0,
            should_convert_after_send_buffer: false,
            early_data: true
        })
    }

    pub async fn negotiate_as_server(
        mut stream: TcpStream,
        rsa_private_key: RsaPrivateKey
    ) -> io::Result<Self> {
        stream.set_nodelay(true)?;

        let mut encrypted_key_packet = [0u8; u16::MAX as usize];
        let encrypted_key_packet_len = Self::read_tls_packet(
            &mut stream,
            &mut encrypted_key_packet
        ).await?;
        if encrypted_key_packet_len <= 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid client's packet"));
        }

        let encrypted_key_len = u16::from_be_bytes([encrypted_key_packet[0], encrypted_key_packet[1]]);
        if encrypted_key_len as usize + 2 > encrypted_key_packet_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid client's packet"));
        }

        let encrypted_key = &encrypted_key_packet[2..encrypted_key_len as usize + 2];
        let key = rsa_private_key.decrypt(
            Pkcs1v15Encrypt,
            &encrypted_key
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid encryption on client's packet"))?;

        let key: [u8; 32] = key.try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid length of client's session key"))?;
        Ok(Self {
            inner: XTlsInnerStream::new(
                Aes256Gcm::new(&Key::<Aes256Gcm>::from(key)),
                stream
            ),
            analyzer: TlsAnalyzer::new(),
            is_client: false,
            send_buffer: Box::new([0u8; 0x5000]),
            send_buffer_position: 0,
            send_buffer_size: 0,
            should_convert_after_send_buffer: false,
            early_data: true
        })
    }

    pub fn end_early_data(&mut self) {
        self.early_data = false
    }

    pub fn stop_tls_detection(&mut self) {
        self.analyzer.force_done();
    }

    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.early_data {
            return self.inner.get_aes_stream().unwrap().try_read(buf);
        }

        if self.analyzer.is_done() {
            match self.inner.get_mut() {
                Ok(s) => s.try_read(buf),
                Err(s) => s.try_read(buf)
            }
        } else {
            let n = self.inner.get_aes_stream().unwrap().try_read(buf)?;
            if n == 0 {
                return Ok(0);
            }
            let tls_status = if self.is_client {
                self.analyzer.write_server(&buf[..n])
            } else {
                self.analyzer.write_client(&buf[..n])
            };
            match tls_status {
                TlsAnalyzerResult::IsTls(split_idx) => {
                    if split_idx != 0 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    self.inner.convert_to_tcp();
                }
                _ => {}
            }
            Ok(n)
        }
    }

    pub fn try_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.send_buffer_size != 0 {
            let n = self.inner
                .get_aes_stream()
                .unwrap()
                .try_write(&buf[self.send_buffer_position..self.send_buffer_size])?;
            if n == 0 {
                return Ok(0);
            }
            self.send_buffer_position += n;
            if self.send_buffer_position == self.send_buffer_size {
                self.send_buffer_size = 0;
                self.send_buffer_position = 0;
                if self.should_convert_after_send_buffer {
                    self.inner.convert_to_tcp();
                }
                self.should_convert_after_send_buffer = false;
                return self.try_write(buf);
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }

        let buf = if buf.len() > 0x4000 - 12 - 16 - 5 {
            &buf[..0x4000 - 12 - 16 - 5]
        } else {
            buf
        };

        if self.early_data {
            return self.inner.get_aes_stream().unwrap().try_write(buf);
        }

        if self.analyzer.is_done() {
            match self.inner.get_mut() {
                Ok(s) => s.try_write(buf),
                Err(s) => s.try_write(buf)
            }
        } else {
            let tls_status = if self.is_client {
                self.analyzer.write_client(buf)
            } else {
                self.analyzer.write_server(buf)
            };
            match tls_status {
                TlsAnalyzerResult::IsTls(split_idx) => {
                    let split_idx = buf.len() - split_idx;
                    let buf = &buf[..split_idx];
                    self.send_buffer[..buf.len()].copy_from_slice(buf);
                    self.send_buffer_size = buf.len();
                    self.should_convert_after_send_buffer = true;
                    let n = self.inner
                        .get_aes_stream()
                        .unwrap()
                        .try_write(buf);
                    let n = match n {
                        Ok(n) => n,
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                return Ok(buf.len());
                            }
                            return Err(e);
                        }
                    };
                    if n == 0 {
                        return Ok(0);
                    }
                    self.send_buffer_position += n;
                    if self.send_buffer_position == self.send_buffer_size {
                        self.send_buffer_size = 0;
                        self.send_buffer_position = 0;
                        self.inner.convert_to_tcp();
                    }
                    Ok(buf.len())
                },
                _ => {
                    self.send_buffer[..buf.len()].copy_from_slice(&buf);
                    self.send_buffer_size = buf.len();
                    let n = self.inner
                        .get_aes_stream()
                        .unwrap()
                        .try_write(&buf[self.send_buffer_position..self.send_buffer_size]);
                    let n = match n {
                        Ok(n) => n,
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                return Ok(buf.len());
                            }
                            return Err(e);
                        }
                    };
                    if n == 0 {
                        return Ok(0);
                    }
                    self.send_buffer_position += n;
                    if self.send_buffer_position == self.send_buffer_size {
                        self.send_buffer_size = 0;
                        self.send_buffer_position = 0;
                    }
                    Ok(buf.len())
                }
            }
        }
    }

    pub async fn writable(&self) -> io::Result<()> {
        match self.inner.get() {
            Ok(s) => s.writable().await,
            Err(s) => s.writable().await,
        }
    }

    pub async fn readable(&self) -> io::Result<()> {
        match self.inner.get() {
            Ok(s) => s.readable().await,
            Err(s) => s.readable().await,
        }
    }

    pub(crate) fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.get() {
            Ok(s) => s.poll_write_ready(cx),
            Err(s) => s.poll_write_ready(cx),
        }
    }

    pub(crate) fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.get() {
            Ok(s) => s.poll_read_ready(cx),
            Err(s) => s.poll_read_ready(cx),
        }
    }
}

impl AsyncRead for XTlsVisionStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            return match self.poll_read_ready(cx) {
                Poll::Ready(Ok(_)) => {
                    let b = buf.initialize_unfilled();
                    match self.try_read(b) {
                        Ok(n) => {
                            buf.advance(n);
                            Poll::Ready(Ok(()))
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                continue;
                            }
                            Poll::Ready(Err(e))
                        }
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending
            }
        }
    }
}

impl AsyncWrite for XTlsVisionStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            return match self.poll_write_ready(cx) {
                Poll::Ready(Ok(_)) => {
                    match self.try_write(buf) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                continue;
                            }
                            Poll::Ready(Err(e))
                        }
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.get_mut() {
            Ok(s) => Pin::new(s).poll_flush(cx),
            Err(s) => Pin::new(s).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            return match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(_)) => {
                    match self.inner.get_mut() {
                        Ok(s) => Pin::new(s).poll_shutdown(cx),
                        Err(s) => Pin::new(s).poll_shutdown(cx)
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, LazyLock};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::client::Resumption;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    static RUSTLS_CLIENT_CONFIG: LazyLock<Arc<ClientConfig>> =
        LazyLock::new(|| {
            let store = RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(store)
                .with_no_client_auth();
            config.resumption = Resumption::disabled();
            Arc::new(config)
        });

    #[tokio::test]
    async fn test_aes_stream() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mut rng = rsa::rand_core::OsRng;
        let mut aes_key = [0u8; 32];
        rng.fill_bytes(&mut aes_key);
        let aes_key = Arc::new(Key::<Aes256Gcm>::from(aes_key));

        let mut client_to_server_buf = vec![0u8; 0x1000000];
        let mut server_to_client_buf = vec![0u8; 0x1000000];
        rng.fill_bytes(&mut client_to_server_buf);
        rng.fill_bytes(&mut server_to_client_buf);
        let client_to_server_buf = Arc::new(client_to_server_buf);
        let server_to_client_buf = Arc::new(server_to_client_buf);
        let client_to_server_buf_clone = client_to_server_buf.clone();
        let server_to_client_buf_clone = server_to_client_buf.clone();

        let aes_key_clone = aes_key.clone();
        let t = tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12345").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut stream = AesTlsTcpStream::new(
                Aes256Gcm::new(&aes_key_clone),
                c
            );
            let mut data = vec![0u8; 0x1000000];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, &*client_to_server_buf_clone);
            stream.write_all(&*server_to_client_buf_clone).await.unwrap();
        });
        ready_rx.await.unwrap();

        let c = TcpStream::connect("127.0.0.1:12345").await.unwrap();
        let mut stream = AesTlsTcpStream::new(
            Aes256Gcm::new(&aes_key),
            c
        );
        stream.write_all(&*client_to_server_buf).await.unwrap();
        let mut data = vec![0u8; 0x1000000];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, &*server_to_client_buf);
        t.await.unwrap();
    }

    #[tokio::test]
    async fn test_pre_tls_threshold() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let rsa_private_key = RsaPrivateKey::new(
            &mut rsa::rand_core::OsRng,
            2048
        ).unwrap();
        let rsa_public_key = rsa_private_key.to_public_key();

        let t = tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12347").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut stream = XTlsVisionStream::negotiate_as_server(
                c,
                rsa_private_key
            ).await.unwrap();
            stream.end_early_data();
            let mut data = [0u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, &[0xde, 0xad, 0xbe, 0xef]);
            stream.write_all(&[0xca, 0xfe, 0xba, 0xbe]).await.unwrap();
        });
        ready_rx.await.unwrap();

        let mut stream = XTlsVisionStream::negotiate_as_client(
            TcpStream::connect("127.0.0.1:12347").await.unwrap(),
            rsa_public_key
        ).await.unwrap();
        stream.end_early_data();
        stream.write_all(&[0xde, 0xad, 0xbe, 0xef]).await.unwrap();
        let mut data = [0u8; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, &[0xca, 0xfe, 0xba, 0xbe]);
        drop(stream);
        t.await.unwrap();
    }

    #[tokio::test]
    async fn test_non_tls() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let rsa_private_key = RsaPrivateKey::new(
            &mut rsa::rand_core::OsRng,
            2048
        ).unwrap();
        let rsa_public_key = rsa_private_key.to_public_key();

        let mut buffer = [0u8; u16::MAX as usize];
        rand::thread_rng().fill_bytes(&mut buffer[..]);
        let buffer = Arc::new(buffer);

        let buffer_clone = buffer.clone();
        let t = tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12348").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut stream = XTlsVisionStream::negotiate_as_server(
                c,
                rsa_private_key
            ).await.unwrap();
            stream.end_early_data();
            let mut data = [0u8; u16::MAX as usize];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, &*buffer_clone);
            stream.write_all(&*buffer_clone).await.unwrap();
        });
        ready_rx.await.unwrap();

        let mut stream = XTlsVisionStream::negotiate_as_client(
            TcpStream::connect("127.0.0.1:12348").await.unwrap(),
            rsa_public_key
        ).await.unwrap();
        stream.end_early_data();
        stream.write_all(&*buffer).await.unwrap();
        let mut data = [0u8; u16::MAX as usize];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, &*buffer);
        drop(stream);
        t.await.unwrap();
    }

    #[tokio::test]
    async fn test_pseudo_tls() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let rsa_private_key = RsaPrivateKey::new(
            &mut rsa::rand_core::OsRng,
            2048
        ).unwrap();
        let rsa_public_key = rsa_private_key.to_public_key();

        tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12349").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut stream = XTlsVisionStream::negotiate_as_server(
                c,
                rsa_private_key
            ).await.unwrap();
            stream.end_early_data();

            let mut client_hello = vec![0u8; u16::MAX as usize + 5];
            stream.read_exact(&mut client_hello[..5]).await.unwrap();
            let n = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize;
            stream.read_exact(&mut client_hello[5..n + 5]).await.unwrap();
            let client_hello = &client_hello[5..n + 5];
            assert!(client_hello.iter().map(|x| *x).eq(std::iter::repeat(0xAAu8).take(2000)));

            let mut server_hello = Vec::new();
            server_hello.extend_from_slice(&[0x16, 0x03, 0x03]);
            server_hello.extend_from_slice(&2000u16.to_be_bytes());
            server_hello.extend(std::iter::repeat(0xBB).take(2000));
            stream.write_all(&server_hello).await.unwrap();

            let mut client_app_data = [0u8; u16::MAX as usize];
            let client_app_data_size = XTlsVisionStream::read_tls_packet(
                &mut stream,
                &mut client_app_data
            ).await.unwrap();
            let client_app_data = &client_app_data[..client_app_data_size];
            assert!(client_app_data.iter().map(|x| *x).eq(std::iter::repeat(0xCC).take(3000)));

            let mut server_app_data = Vec::new();
            server_app_data.extend_from_slice(&[0x17, 0x03, 0x03]);
            server_app_data.extend_from_slice(&3000u16.to_be_bytes());
            server_app_data.extend(std::iter::repeat(0xDD).take(3000));
            stream.write_all(&server_app_data).await.unwrap();

            assert!(stream.inner.tcp_stream.is_some());

            let mut client_app_data_2 = vec![0u8; 3000];
            stream.read_exact(&mut client_app_data_2).await.unwrap();
            assert!(client_app_data_2.iter().map(|x| *x).eq(std::iter::repeat(0xEEu8).take(3000)));

            stream.write_all(&std::iter::repeat(0xFFu8).take(3000).collect::<Vec<u8>>()).await.unwrap();
        });
        ready_rx.await.unwrap();

        let mut stream = XTlsVisionStream::negotiate_as_client(
            TcpStream::connect("127.0.0.1:12349").await.unwrap(),
            rsa_public_key
        ).await.unwrap();
        stream.end_early_data();

        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&[0x16, 0x03, 0x03]);
        client_hello.extend_from_slice(&2000u16.to_be_bytes());
        client_hello.extend(std::iter::repeat(0xAA).take(2000));
        stream.write_all(&client_hello).await.unwrap();

        let mut server_hello = [0u8; u16::MAX as usize];
        let server_hello_size = XTlsVisionStream::read_tls_packet(
            &mut stream,
            &mut server_hello
        ).await.unwrap();
        let server_hello = &server_hello[..server_hello_size];
        assert!(server_hello.iter().map(|x| *x).eq(std::iter::repeat(0xBB).take(2000)));

        let mut client_app_data = Vec::new();
        client_app_data.extend_from_slice(&[0x17, 0x03, 0x03]);
        client_app_data.extend_from_slice(&3000u16.to_be_bytes());
        client_app_data.extend(std::iter::repeat(0xCC).take(3000));
        stream.write_all(&client_app_data).await.unwrap();

        let mut server_app_data = [0u8; u16::MAX as usize];
        let server_app_data_size = XTlsVisionStream::read_tls_packet(
            &mut stream,
            &mut server_app_data
        ).await.unwrap();
        let server_app_data = &server_app_data[..server_app_data_size];
        assert!(server_app_data.iter().map(|x| *x).eq(std::iter::repeat(0xDD).take(3000)));

        assert!(stream.inner.tcp_stream.is_some());

        stream.write_all(&std::iter::repeat(0xEEu8).take(3000).collect::<Vec<u8>>()).await.unwrap();

        let mut server_app_data_2 = vec![0u8; 3000];
        stream.read_exact(&mut server_app_data_2).await.unwrap();
        assert!(server_app_data_2.iter().map(|x| *x).eq(std::iter::repeat(0xFFu8).take(3000)));
    }

    #[tokio::test]
    async fn test_tls_ifconfig() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let rsa_private_key = RsaPrivateKey::new(
            &mut rsa::rand_core::OsRng,
            2048
        ).unwrap();
        let rsa_public_key = rsa_private_key.to_public_key();

        tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12350").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut stream = XTlsVisionStream::negotiate_as_server(
                c,
                rsa_private_key
            ).await.unwrap();
            stream.end_early_data();

            let mut actual_server = TcpStream::connect("ifconfig.me:443").await.unwrap();

            let _ = tokio::io::copy_bidirectional(&mut stream, &mut actual_server).await;
        });
        ready_rx.await.unwrap();

        let mut c = XTlsVisionStream::negotiate_as_client(
            TcpStream::connect("127.0.0.1:12350").await.unwrap(),
            rsa_public_key
        ).await.unwrap();
        c.end_early_data();

        let hostname = ServerName::try_from("ifconfig.me")
            .unwrap()
            .to_owned();
        let tls_client = TlsConnector::from(
            RUSTLS_CLIENT_CONFIG.clone()
        );
        let mut tls_client = tls_client.connect(hostname, c).await.unwrap();

        tls_client.write_all(b"GET / HTTP/1.1\r\nHost: www.ifconfig.me\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 0x10000];
        let n = tls_client.read(&mut buf).await.unwrap();
        let buf = String::from_utf8_lossy(&buf[..n]);
        println!("TLS TEST DATA:\n{}\nEND OF TLS TEST DATA\nEnsure it's a valid response from ifconfig.me", buf);
    }

    #[tokio::test]
    async fn test_tls_google() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let rsa_private_key = RsaPrivateKey::new(
            &mut rsa::rand_core::OsRng,
            2048
        ).unwrap();
        let rsa_public_key = rsa_private_key.to_public_key();

        tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12351").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut stream = XTlsVisionStream::negotiate_as_server(
                c,
                rsa_private_key
            ).await.unwrap();
            stream.end_early_data();

            let mut actual_server = TcpStream::connect("google.com:443").await.unwrap();

            let _ = tokio::io::copy_bidirectional(&mut stream, &mut actual_server).await;
        });
        ready_rx.await.unwrap();

        let mut c = XTlsVisionStream::negotiate_as_client(
            TcpStream::connect("127.0.0.1:12351").await.unwrap(),
            rsa_public_key
        ).await.unwrap();
        c.end_early_data();

        let hostname = ServerName::try_from("google.com")
            .unwrap()
            .to_owned();
        let tls_client = TlsConnector::from(
            RUSTLS_CLIENT_CONFIG.clone()
        );
        let mut tls_client = tls_client.connect(hostname, c).await.unwrap();

        tls_client.write_all(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 0x10000];
        let n = tls_client.read(&mut buf).await.unwrap();
        let buf = String::from_utf8_lossy(&buf[..n]);
        println!("TLS TEST DATA:\n{}\nEND OF TLS TEST DATA\nEnsure it's a valid response from google.com", buf);
    }
}
