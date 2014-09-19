#[test]
fn smoke() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.flush().unwrap();
    channel.exec("true").unwrap();
    channel.wait_eof().unwrap();
    assert!(channel.eof());
    assert_eq!(channel.exit_status().unwrap(), 0);
    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert!(channel.eof());
}

#[test]
fn reading_data() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("echo foo").unwrap();
    let output = channel.read_to_string().unwrap();
    assert_eq!(output.as_slice(), "foo\n");
}

#[test]
fn writing_data() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("read foo && echo $foo").unwrap();
    channel.write(b"foo\n").unwrap();
    channel.close().unwrap();
    let output = channel.read_to_string().unwrap();
    assert_eq!(output.as_slice(), "foo\n");
}

#[test]
fn eof() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("read foo").unwrap();
    channel.send_eof().unwrap();
    let output = channel.read_to_string().unwrap();
    assert_eq!(output.as_slice(), "");
}

#[test]
fn shell() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.shell().unwrap();
}

#[test]
fn setenv() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    let _ = channel.setenv("FOO", "BAR");
}
