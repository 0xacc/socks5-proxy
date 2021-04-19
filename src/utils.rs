use std::io::{self, Result};
use std::net::SocketAddr;
use thiserror::Error;

pub const SOCKS_VER: u8 = 0x05;
pub const SOCKS_RSV: u8 = 0x00;
pub const SOCKS_COMMAND_CONNECT: u8 = 0x01;
pub const SOCKS_ADDR_IPV4: u8 = 0x01;
pub const SOCKS_ADDR_IPV6: u8 = 0x04;
pub const SOCKS_ADDR_DOMAINNAME: u8 = 0x03;

pub enum Addr {
    SocketAddr(SocketAddr),
    HostnamePort(String),
}
#[derive(Debug)]
pub enum AuthMethod {
    NoAuth,
    UserPass(Option<(String, String)>),
    NoAvailable,
}
impl AuthMethod {
    pub fn to_code(&self) -> u8 {
        use AuthMethod::*;
        match self {
            NoAuth => 0x00,
            UserPass(_) => 0x02,
            NoAvailable => 0xFF,
        }
    }
    pub fn from_code(code: u8) -> Result<AuthMethod> {
        use AuthMethod::*;
        match code {
            0x00 => Ok(NoAuth),
            0x02 => Ok(UserPass(None)),
            0xFF => Ok(NoAvailable),
            _ => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("unsupported authenticate method {:#04X?}", code),
            )),
        }
    }
}
#[derive(Error, Debug)]
pub enum SocksError {
    #[error("succeeded")]
    SUCCESS = 0x00,
    #[error("general SOCKS server failure")]
    FAIL = 0x01,
    #[error("connection not allowed by ruleset")]
    DENY = 0x02,
    #[error("Network unreachable")]
    NETWORK = 0x03,
    #[error("Host unreachable")]
    HOST = 0x04,
    #[error("Connection refused")]
    CONNECTION = 0x05,
    #[error("TTL expired")]
    TTL = 0x06,
    #[error("Command not supported")]
    COMMAND = 0x07,
    #[error("Address type not supported")]
    ADDRESS = 0x08,
    #[error("unkown error")]
    OTHOR,
}

impl Into<io::Error> for SocksError {
    fn into(self) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, self)
    }
}

impl From<u8> for SocksError {
    fn from(code: u8) -> Self {
        use SocksError::*;
        match code {
            0x01 => FAIL,
            0x02 => DENY,
            0x03 => NETWORK,
            0x04 => HOST,
            0x05 => CONNECTION,
            0x06 => TTL,
            0x07 => COMMAND,
            0x08 => ADDRESS,
            _ => OTHOR,
        }
    }
}

pub struct Buffer<'a> {
    buffer: &'a mut [u8],
    pos: usize,
}
impl<'a> Buffer<'a> {
    #[inline]
    pub fn from(buffer: &mut [u8]) -> Buffer {
        Buffer { buffer, pos: 0 }
    }
    #[inline]
    pub fn content(self) -> &'a [u8] {
        &self.buffer[..self.pos]
    }
    #[inline]
    pub fn push(&mut self, byte: u8) {
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }
    #[inline]
    pub fn extend(&mut self, slice: &[u8]) {
        let end = self.pos + slice.len();
        self.buffer[self.pos..end].clone_from_slice(slice);
        self.pos = end;
    }
}

macro_rules! impl_deref {
    ($x:tt,$y:ty) => {
        struct $x($y);
        impl Deref for $x {
            type Target = $y;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl DerefMut for $x {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}
