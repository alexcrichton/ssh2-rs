#[test]
fn smoke() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.flush().unwrap();
    channel.exec("true").unwrap();
    channel.wait_eof().unwrap();
    assert_eq!(channel.exit_status().unwrap(), 0);
    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert!(channel.eof());
}
