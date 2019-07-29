#![deny(warnings)]

extern crate ssh2;
extern crate tempdir;

use std::env;
use std::net::TcpStream;

mod agent;
mod channel;
mod knownhosts;
mod session;
mod sftp;

pub fn socket() -> TcpStream {
    let port = env::var("RUST_SSH2_FIXTURE_PORT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(22);
    TcpStream::connect(&format!("127.0.0.1:{}", port)).unwrap()
}

pub fn authed_session() -> ssh2::Session {
    let user = env::var("USER").unwrap();
    let socket = socket();
    let mut sess = ssh2::Session::new().unwrap();
    sess.handshake(socket).unwrap();
    assert!(!sess.authenticated());

    {
        let mut agent = sess.agent().unwrap();
        agent.connect().unwrap();
        agent.list_identities().unwrap();
        let identity = agent.identities().next().unwrap().unwrap();
        agent.userauth(&user, &identity).unwrap();
    }
    assert!(sess.authenticated());
    sess
}
