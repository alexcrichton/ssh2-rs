extern crate ssh2;
extern crate native;
extern crate rustrt;

use rustrt::rtio::{SocketAddr, Ipv4Addr};
use native::io::net::TcpStream;

mod agent;
mod session;

pub fn socket() -> TcpStream {
    let stream = TcpStream::connect(SocketAddr {
        ip: Ipv4Addr(127, 0, 0, 1),
        port: 22,
    }, None);
    match stream {
        Ok(s) => s,
        Err(e) => fail!("no socket: [{}]: {}", e.code, e.detail),
    }
}
