use std::io::{TcpListener, Listener, Acceptor, TcpStream};
use std::thread::Thread;

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
    channel.adjust_receive_window(10, false).unwrap();
    channel.exec("read foo").unwrap();
    channel.send_eof().unwrap();
    let output = channel.read_to_string().unwrap();
    assert_eq!(output.as_slice(), "");
}

#[test]
fn shell() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.request_pty("xterm", None, None).unwrap();
    channel.shell().unwrap();
}

#[test]
fn setenv() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    let _ = channel.setenv("FOO", "BAR");
    channel.close().unwrap();
}

#[test]
fn direct() {
    let mut l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.socket_name().unwrap();
    let mut a = l.listen().unwrap();
    let t = Thread::spawn(move|| {
        let mut s = a.accept().unwrap();
        let b = &mut [0, 0, 0];
        s.read(b).unwrap();
        assert_eq!(b.as_slice(), [1, 2, 3].as_slice());
        s.write(&[4, 5, 6]).unwrap();
    });
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_direct_tcpip("127.0.0.1",
                                                addr.port, None).unwrap();
    channel.write(&[1, 2, 3]).unwrap();
    let r = &mut [0, 0, 0];
    channel.read(r).unwrap();
    assert_eq!(r.as_slice(), [4, 5, 6].as_slice());
    t.join().ok().unwrap();
}

#[test]
fn forward() {
    let (_tcp, sess) = ::authed_session();
    let (mut listen, port) = sess.channel_forward_listen(39249, None, None)
                                 .unwrap();
    let t = Thread::spawn(move|| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let b = &mut [0, 0, 0];
        s.read(b).unwrap();
        assert_eq!(b.as_slice(), [1, 2, 3].as_slice());
        s.write(&[4, 5, 6]).unwrap();
    });

    let mut channel = listen.accept().unwrap();
    channel.write(&[1, 2, 3]).unwrap();
    let r = &mut [0, 0, 0];
    channel.read(r).unwrap();
    assert_eq!(r.as_slice(), [4, 5, 6].as_slice());
    t.join().ok().unwrap();
}
