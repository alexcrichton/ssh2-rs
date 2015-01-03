use std::os;
use std::io::{self, File, TempDir};

use ssh2::{self, Session, MethodType, HashType};

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    assert!(sess.banner_bytes().is_none());
    sess.set_banner("foo").unwrap();
    assert!(sess.is_blocking());
    assert_eq!(sess.timeout(), 0);
    sess.flag(ssh2::SessionFlag::Compress, true).unwrap();
    assert!(sess.host_key().is_none());
    sess.method_pref(MethodType::Kex, "diffie-hellman-group14-sha1").unwrap();
    assert!(sess.methods(MethodType::Kex).is_none());
    sess.set_blocking(true);
    sess.set_timeout(0);
    sess.supported_algs(MethodType::Kex).unwrap();
    sess.supported_algs(MethodType::HostKey).unwrap();
    sess.channel_session().err().unwrap();
}

#[test]
fn smoke_handshake() {
    let user = os::getenv("USER").unwrap();
    let mut sess = Session::new().unwrap();
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
    sess.host_key_hash(HashType::Md5).unwrap();
}

#[test]
fn keepalive() {
    let (_tcp, sess) = ::authed_session();
    sess.keepalive_set(false, 10).unwrap();
    sess.keepalive_send().unwrap();
}

#[test]
fn scp_recv() {
    let (_tcp, sess) = ::authed_session();
    let (mut ch, _) = sess.scp_recv(&Path::new(".ssh/authorized_keys")).unwrap();
    let data = ch.read_to_string().unwrap();
    let p = Path::new(os::getenv("HOME").unwrap()).join(".ssh/authorized_keys");
    let expected = File::open(&p).read_to_string().unwrap();
    assert!(data == expected);
}

#[test]
fn scp_send() {
    let td = TempDir::new("test").unwrap();
    let (_tcp, sess) = ::authed_session();
    let mut ch = sess.scp_send(&td.path().join("foo"),
                               io::USER_FILE, 6, None).unwrap();
    ch.write(b"foobar").unwrap();
    drop(ch);
    let actual = File::open(&td.path().join("foo")).read_to_end().unwrap();
    assert_eq!(actual.as_slice(), b"foobar");
}
