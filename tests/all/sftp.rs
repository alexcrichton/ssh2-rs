use std::io::prelude::*;
use std::fs::{self, File};
use tempdir::TempDir;

#[test]
fn smoke() {
    let (_tcp, sess) = ::authed_session();
    sess.sftp().unwrap();
}

#[test]
fn ops() {
    let td = TempDir::new("foo").unwrap();
    File::create(&td.path().join("foo")).unwrap();
    fs::create_dir(&td.path().join("bar")).unwrap();

    let (_tcp, sess) = ::authed_session();
    let sftp = sess.sftp().unwrap();
    sftp.opendir(&td.path().join("bar")).unwrap();
    let mut foo = sftp.open(&td.path().join("foo")).unwrap();
    sftp.mkdir(&td.path().join("bar2"), 0o755).unwrap();
    assert!(fs::metadata(&td.path().join("bar2")).map(|m| m.is_dir())
               .unwrap_or(false));
    sftp.rmdir(&td.path().join("bar2")).unwrap();

    sftp.create(&td.path().join("foo5")).unwrap().write_all(b"foo").unwrap();
    let mut v = Vec::new();
    File::open(&td.path().join("foo5")).unwrap().read_to_end(&mut v).unwrap();
    assert_eq!(v, b"foo");

    assert_eq!(sftp.stat(&td.path().join("foo")).unwrap().size, Some(0));
    v.truncate(0);
    foo.read_to_end(&mut v).unwrap();
    assert_eq!(v, Vec::new());

    sftp.symlink(&td.path().join("foo"),
                 &td.path().join("foo2")).unwrap();
    let readlink = sftp.readlink(&td.path().join("foo2")).unwrap();
    assert!(readlink == td.path().join("foo"));
    let realpath = sftp.realpath(&td.path().join("foo2")).unwrap();
    assert_eq!(realpath, td.path().join("foo").canonicalize().unwrap());

    let files = sftp.readdir(td.path()).unwrap();
    assert_eq!(files.len(), 4);
}
