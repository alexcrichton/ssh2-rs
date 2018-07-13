use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

use ssh2::{Session, MethodType, HashType};

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    assert!(sess.banner_bytes().is_none());
    sess.set_banner("foo").unwrap();
    assert!(sess.is_blocking());
    assert_eq!(sess.timeout(), 0);
    sess.set_compress(true);
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
    let user = env::var("USER").unwrap();
    let socket = ::socket();
    let mut sess = Session::new().unwrap();
    sess.handshake(&socket).unwrap();
    sess.host_key().unwrap();
    let methods = sess.auth_methods(&user).unwrap();
    assert!(methods.contains("publickey"), "{}", methods);
    assert!(!sess.authenticated());

    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();
    {
        let identity = agent.identities().next().unwrap().unwrap();
        agent.userauth(&user, &identity).unwrap();
    }
    assert!(sess.authenticated());
    sess.host_key_hash(HashType::Md5).unwrap();
}

#[test]
fn keepalive() {
    let (_tcp, sess) = ::authed_session();
    sess.set_keepalive(false, 10);
    sess.keepalive_send().unwrap();
}

#[test]
fn scp_recv() {
    let (_tcp, sess) = ::authed_session();
    let (mut ch, _) = sess.scp_recv(Path::new(".ssh/authorized_keys")).unwrap();
    let mut data = String::new();
    ch.read_to_string(&mut data).unwrap();
    let p = PathBuf::from(env::var("HOME").unwrap()).join(".ssh/authorized_keys");
    let mut expected = String::new();
    File::open(&p).unwrap().read_to_string(&mut expected).unwrap();
    assert!(data == expected);
}

#[test]
fn scp_send() {
    let td = TempDir::new("test").unwrap();
    let (_tcp, sess) = ::authed_session();
    let mut ch = sess.scp_send(&td.path().join("foo"), 0o644, 6, None).unwrap();
    ch.write_all(b"foobar").unwrap();
    drop(ch);
    let mut actual = Vec::new();
    File::open(&td.path().join("foo")).unwrap().read_to_end(&mut actual).unwrap();
    assert_eq!(actual, b"foobar");
}
