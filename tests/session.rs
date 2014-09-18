use std::os;

use ssh2::{mod, Session};

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    assert!(sess.banner_bytes().is_none());
    sess.set_banner("foo").unwrap();
    assert!(sess.is_blocking());
    assert_eq!(sess.timeout(), 0);
    sess.flag(ssh2::Compress, true).unwrap();
    assert!(sess.host_key().is_none());
    sess.method_pref(ssh2::MethodKex, "diffie-hellman-group14-sha1").unwrap();
    assert!(sess.methods(ssh2::MethodKex).is_none());
    sess.set_blocking(true);
    sess.set_timeout(0);
    sess.supported_algs(ssh2::MethodKex).unwrap();
    sess.supported_algs(ssh2::MethodHostKey).unwrap();
    sess.channel_session().err().unwrap();
}

#[test]
fn smoke_handshake() {
    let user = os::getenv("USER").unwrap();
    let sess = Session::new().unwrap();
    let socket = ::socket();
    sess.handshake(socket.fd()).unwrap();
    sess.host_key().unwrap();
    let methods = sess.auth_methods(user.as_slice()).unwrap();
    assert!(methods.contains("publickey"), "{}", methods);
    assert!(!sess.authenticated());

    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();
    {
        let identity = agent.identities().next().unwrap().unwrap();
        agent.userauth(user.as_slice(), &identity).unwrap();
    }
    assert!(sess.authenticated());
}
