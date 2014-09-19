extern crate ssh2;
extern crate native;
extern crate rustrt;

use std::os;
use rustrt::rtio::{SocketAddr, Ipv4Addr};
use native::io::net::TcpStream;

mod agent;
mod session;
mod channel;
mod knownhosts;
mod sftp;

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

pub fn authed_session() -> (TcpStream, ssh2::Session) {
    let user = os::getenv("USER").unwrap();
    let mut sess = ssh2::Session::new().unwrap();
    let socket = socket();
    sess.handshake(socket.fd()).unwrap();
    assert!(!sess.authenticated());

    {
        let mut agent = sess.agent().unwrap();
        agent.connect().unwrap();
        agent.list_identities().unwrap();
        let identity = agent.identities().next().unwrap().unwrap();
        agent.userauth(user.as_slice(), &identity).unwrap();
    }
    assert!(sess.authenticated());
    (socket, sess)
}
