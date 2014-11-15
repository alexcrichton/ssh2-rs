extern crate ssh2;
extern crate libc;

use std::mem;
use std::num::Int;
use std::os;

mod agent;
mod session;
mod channel;
mod knownhosts;
mod sftp;

pub struct TcpStream(libc::c_int);

pub fn socket() -> TcpStream {
    unsafe {
        let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(socket != -1, "{} {}", os::errno(), os::last_os_error());

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 22.to_be(),
            sin_addr: libc::in_addr {
                s_addr: 0x7f000001.to_be(),
            },
            ..mem::zeroed()
        };

        let r = libc::connect(socket, &addr as *const _ as *const _,
                              mem::size_of_val(&addr) as libc::c_uint);
        assert!(r != -1, "{} {}", os::errno(), os::last_os_error());
        TcpStream(socket)
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

impl TcpStream {
    fn fd(&self) -> libc::c_int { let TcpStream(fd) = *self; fd }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd()); }
    }
}
