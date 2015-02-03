#![deny(warnings)]
#![feature(io, core, path, os, std_misc, libc)]

extern crate ssh2;
extern crate libc;

use std::os;
use std::old_io::TcpStream;

mod agent;
mod session;
mod channel;
mod knownhosts;
mod sftp;

pub fn socket() -> TcpStream {
    TcpStream::connect("127.0.0.1:22").unwrap()
}

pub fn authed_session() -> (TcpStream, ssh2::Session) {
    let user = os::getenv("USER").unwrap();
    let socket = socket();
    let mut sess = ssh2::Session::new().unwrap();
    sess.handshake(&socket).unwrap();
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
