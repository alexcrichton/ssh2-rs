use std::fs::{self, File};
use std::io::prelude::*;
use tempfile::TempDir;

#[test]
fn smoke() {
    let sess = ::authed_session();
    sess.sftp().unwrap();
}

#[test]
fn ops() {
    let td = TempDir::new().unwrap();
    File::create(&td.path().join("foo")).unwrap();
    fs::create_dir(&td.path().join("bar")).unwrap();

    let sess = ::authed_session();
    let sftp = sess.sftp().unwrap();
    sftp.opendir(&td.path().join("bar")).unwrap();
    let mut foo = sftp.open(&td.path().join("foo")).unwrap();
    sftp.mkdir(&td.path().join("bar2"), 0o755).unwrap();
    assert!(fs::metadata(&td.path().join("bar2"))
        .map(|m| m.is_dir())
        .unwrap_or(false));
    sftp.rmdir(&td.path().join("bar2")).unwrap();

    sftp.create(&td.path().join("foo5"))
        .unwrap()
        .write_all(b"foo")
        .unwrap();
    let mut v = Vec::new();
    File::open(&td.path().join("foo5"))
        .unwrap()
        .read_to_end(&mut v)
        .unwrap();
    assert_eq!(v, b"foo");

    assert_eq!(sftp.stat(&td.path().join("foo")).unwrap().size, Some(0));
    v.truncate(0);
    foo.read_to_end(&mut v).unwrap();
    assert_eq!(v, Vec::new());

    sftp.symlink(&td.path().join("foo"), &td.path().join("foo2"))
        .unwrap();
    let readlink = sftp.readlink(&td.path().join("foo2")).unwrap();
    assert!(readlink == td.path().join("foo"));
    let realpath = sftp.realpath(&td.path().join("foo2")).unwrap();
    assert_eq!(realpath, td.path().join("foo").canonicalize().unwrap());

    let files = sftp.readdir(td.path()).unwrap();
    assert_eq!(files.len(), 4);
}

#[test]
fn not_found() {
    let td = TempDir::new().unwrap();

    let sess = ::authed_session();
    let sftp = sess.sftp().unwrap();

    // Can't use unwrap_err here since File does not impl Debug.
    let err = sftp
        .opendir(&td.path().join("nonexistent"))
        .err()
        .expect("open nonexistent dir");
    assert_eq!(err.to_string(), "[SFTP(2)] no such file");

    let io_err: std::io::Error = err.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(io_err.to_string(), "no such file");

    let err = sftp
        .stat(&td.path().join("nonexistent"))
        .err()
        .expect("stat nonexistent");
    assert_eq!(err.to_string(), "[SFTP(2)] no such file");
    let io_err: std::io::Error = err.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(io_err.to_string(), "no such file");
}
