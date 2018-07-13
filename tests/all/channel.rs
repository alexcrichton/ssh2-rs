use std::io::prelude::*;
use std::net::{TcpStream, TcpListener};
use std::thread;

#[test]
fn smoke() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.flush().unwrap();
    channel.exec("true").unwrap();
    channel.wait_eof().unwrap();
    assert!(channel.eof());
    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert_eq!(channel.exit_status().unwrap(), 0);
    assert!(channel.eof());
}

#[test]
fn bad_smoke() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.flush().unwrap();
    channel.exec("false").unwrap();
    channel.wait_eof().unwrap();
    assert!(channel.eof());
    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert_eq!(channel.exit_status().unwrap(), 1);
    assert!(channel.eof());
}

#[test]
fn reading_data() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("echo foo").unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    assert_eq!(output, "foo\n");
}

#[test]
fn writing_data() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("read foo && echo $foo").unwrap();
    channel.write_all(b"foo\n").unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    assert_eq!(output, "foo\n");
}

#[test]
fn eof() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.adjust_receive_window(10, false).unwrap();
    channel.exec("read foo").unwrap();
    channel.send_eof().unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    assert_eq!(output, "");
}

#[test]
fn shell() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.request_pty("xterm", None, None).unwrap();
    channel.shell().unwrap();
    channel.close().unwrap();
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
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = a.local_addr().unwrap();
    let t = thread::spawn(move|| {
        let mut s = a.accept().unwrap().0;
        let mut b = [0, 0, 0];
        s.read(&mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
        s.write_all(&[4, 5, 6]).unwrap();
    });
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_direct_tcpip("127.0.0.1",
                                                addr.port(), None).unwrap();
    channel.write_all(&[1, 2, 3]).unwrap();
    let mut r = [0, 0, 0];
    channel.read(&mut r).unwrap();
    assert_eq!(r, [4, 5, 6]);
    t.join().ok().unwrap();
}

#[test]
fn forward() {
    let (_tcp, sess) = ::authed_session();
    let (mut listen, port) = sess.channel_forward_listen(39249, None, None)
                                 .unwrap();
    let t = thread::spawn(move|| {
        let mut s = TcpStream::connect(&("127.0.0.1", port)).unwrap();
        let mut b = [0, 0, 0];
        s.read(&mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
        s.write_all(&[4, 5, 6]).unwrap();
    });

    let mut channel = listen.accept().unwrap();
    channel.write_all(&[1, 2, 3]).unwrap();
    let mut r = [0, 0, 0];
    channel.read(&mut r).unwrap();
    assert_eq!(r, [4, 5, 6]);
    t.join().ok().unwrap();
}

#[test]
fn drop_nonblocking() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (_tcp, sess) = ::authed_session();
    sess.set_blocking(false);

    thread::spawn(move || {
        let _s = listener.accept().unwrap();
    });

    let _ = sess.channel_direct_tcpip("127.0.0.1", addr.port(), None);
    drop(sess);
}

#[test]
fn nonblocking_before_exit_code() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.send_eof().unwrap();
    let mut output = String::new();

    channel.exec("sleep 1; echo foo").unwrap();
    sess.set_blocking(false);
    assert!(channel.read_to_string(&mut output).is_err());
    {
        use std::time::Duration;
        use std::thread;
        thread::sleep(Duration::from_millis(1500));
    }
    sess.set_blocking(true);
    assert!(channel.read_to_string(&mut output).is_ok());

    channel.wait_eof().unwrap();
    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert_eq!(output, "foo\n");
    assert!(channel.exit_status().unwrap() == 0);
}

#[test]
fn exit_code_ignores_other_errors() {
    let (_tcp, sess) = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("true").unwrap();
    channel.wait_eof().unwrap();
    channel.close().unwrap();
    channel.wait_close().unwrap();
    let longdescription: String = ::std::iter::repeat('a').take(300).collect();
    assert!(sess.disconnect(None, &longdescription, None).is_err()); // max len == 256
    assert!(channel.exit_status().unwrap() == 0);
}
