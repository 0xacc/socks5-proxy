use crate::utils::*;

use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Result},
    net::{TcpStream, ToSocketAddrs},
};

pub async fn new(
    server: impl ToSocketAddrs,
    dest: &Addr,
    auth: Option<AuthMethod>,
) -> Result<TcpStream> {
    let conn = TcpStream::connect(server).await?;
    let auth = auth.unwrap_or(AuthMethod::NoAuth);

    let client = PendingHandshake(conn);
    let client = client.handshake(&auth).await?;
    let client = client.authenticate(&auth).await?;
    let client = client.connect(dest).await?;

    Ok(client)
}

impl_deref!(PendingHandshake, TcpStream);
impl PendingHandshake {
    #[inline]
    async fn handshake(mut self, method: &AuthMethod) -> Result<PendingAuthenticate> {
        let msg: &[u8] = &[SOCKS_VER, 0x01, method.to_code()];
        self.write_all(msg).await?;
        self.flush().await?;

        let mut buffer = [0; 2];
        self.read_exact(&mut buffer).await?;

        if buffer[0] != SOCKS_VER {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "unsupported protocol",
            ));
        }

        let auth = AuthMethod::from_code(buffer[1])?;

        if let AuthMethod::NoAvailable = auth {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "no supported authenticate method available",
            ))
        } else if auth.to_code() != method.to_code() {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "unsupported protocol",
            ))
        } else {
            Ok(PendingAuthenticate(self.0))
        }
    }
}

impl_deref!(PendingAuthenticate, TcpStream);
impl PendingAuthenticate {
    #[inline]
    async fn authenticate(self, auth: &AuthMethod) -> Result<PendingConnect> {
        match auth {
            AuthMethod::NoAuth => Ok(PendingConnect(self.0)),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("authenticate method {:?} not implemented", &auth),
            )),
        }
    }
}

impl_deref!(PendingConnect, TcpStream);
impl PendingConnect {
    #[inline]
    async fn connect(mut self, dest: &Addr) -> Result<TcpStream> {
        let mut buffer = [0u8; 4 + 255 + 2];
        let mut request = Buffer::from(&mut buffer);
        request.extend(&[SOCKS_RSV, SOCKS_COMMAND_CONNECT, SOCKS_RSV]);

        parse_dest(&mut request, dest)?;

        self.write_all(request.content()).await?;
        self.flush().await?;

        let header: &mut [u8] = &mut buffer[..4];

        self.read_exact(header).await?;

        if header[0] != SOCKS_VER || header[02] != SOCKS_RSV {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "unsupported protocol",
            ));
        }
        if header[1] != SocksError::SUCCESS as u8 {
            return Err(SocksError::from(header[1]).into());
        }

        self.extract_address(header[3], &mut buffer).await?;

        Ok(self.0)
    }

    async fn extract_address(&mut self, addr_type: u8, buffer: &mut [u8]) -> Result<()> {
        match addr_type {
            SOCKS_ADDR_IPV4 => self.read_exact(&mut buffer[..4 + 2]).await?,
            SOCKS_ADDR_IPV6 => self.read_exact(&mut buffer[..16 + 2]).await?,
            SOCKS_ADDR_DOMAINNAME => {
                self.read_exact(&mut buffer[..1]).await?;
                let len = buffer[0] as usize;
                self.read_exact(&mut buffer[..(len + 2)]).await?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "unsupported address type",
                ))
            }
        };
        Ok(())
    }
}

macro_rules! write_addr_binary {
    ($buffer:ident,$addr_type:ident,$addr:ident) => {{
        $buffer.push($addr_type);
        $buffer.extend(&$addr.ip().octets());
        $buffer.extend(&$addr.port().to_be_bytes());
    }};
}

#[inline]
fn parse_dest(request: &mut Buffer, dest: &Addr) -> Result<()> {
    match dest {
        Addr::SocketAddr(addr) => {
            match addr {
                SocketAddr::V4(v4) => write_addr_binary!(request, SOCKS_ADDR_IPV4, v4),
                SocketAddr::V6(v6) => write_addr_binary!(request, SOCKS_ADDR_IPV6, v6),
            };
        }
        Addr::HostnamePort(hostname_port) => {
            request.push(SOCKS_ADDR_DOMAINNAME);
            let mut hostname_port = hostname_port.split(":");
            let parse_err =
                io::Error::new(io::ErrorKind::InvalidInput, "bad pattern in hostname:port");
            let hostname = hostname_port.next();
            let port = hostname_port.next();
            let none = hostname_port.next();

            if let (Some(hostname), Some(port), None) = (hostname, port, none) {
                let hostname = hostname.as_bytes();
                if hostname.len() > u8::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "hostname too long",
                    ));
                }
                request.push(hostname.len() as u8);
                request.extend(hostname);
                let port = port.parse::<u16>().map_err(|_| parse_err)?;
                request.extend(&port.to_be_bytes());
            } else {
                return Err(parse_err);
            }
        }
    }
    Ok(())
}
