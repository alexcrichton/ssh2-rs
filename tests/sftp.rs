use std::io::{mod, fs, File, TempDir};
use std::io::fs::PathExtensions;

#[test]
fn smoke() {
    let (_tcp, sess) = ::authed_session();
    sess.sftp().unwrap();
}

#[test]
fn ops() {
    let td = TempDir::new("foo").unwrap();
    File::create(&td.path().join("foo")).unwrap();
    fs::mkdir(&td.path().join("bar"), io::USER_DIR).unwrap();

    let (_tcp, sess) = ::authed_session();
    let sftp = sess.sftp().unwrap();
    sftp.opendir(&td.path().join("bar")).unwrap();
    let mut foo = sftp.open(&td.path().join("foo")).unwrap();
    sftp.mkdir(&td.path().join("bar2"), io::USER_DIR).unwrap();
    assert!(td.path().join("bar2").is_dir());
    sftp.rmdir(&td.path().join("bar2")).unwrap();

    sftp.create(&td.path().join("foo5")).unwrap().write(b"foo").unwrap();
    assert_eq!(File::open(&td.path().join("foo5")).read_to_end().unwrap(),
               b"foo".to_vec());

    assert_eq!(sftp.stat(&td.path().join("foo")).unwrap().size, Some(0));
    assert_eq!(foo.read_to_end().unwrap(), Vec::new());

    sftp.symlink(&td.path().join("foo"),
                 &td.path().join("foo2")).unwrap();
    let readlink = sftp.readlink(&td.path().join("foo2")).unwrap();
    assert!(readlink == td.path().join("foo"));
    let realpath = sftp.realpath(&td.path().join("foo2")).unwrap();
    assert!(realpath == td.path().join("foo"));

    let files = sftp.readdir(td.path()).unwrap();
    assert_eq!(files.len(), 4);
}
