#[test]
fn smoke() {
    let (_tcp, sess) = ::authed_session();
    sess.sftp().unwrap();
}
