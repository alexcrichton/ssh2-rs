use ssh2::{Session, KnownHostFileKind};

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    let hosts = sess.known_hosts().unwrap();
    assert_eq!(hosts.iter().count(), 0);
}

#[test]
fn reading() {
    let encoded = "\
|1|VXwDpq2cv4j3QtmrGiY+HntJc+Q=|80E+wqnFDhkxBDxRBOIPJPAVE6Y= \
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9I\
DSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVD\
BfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eF\
zLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKS\
CZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2R\
PW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi\
/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
";
    let sess = Session::new().unwrap();
    let mut hosts = sess.known_hosts().unwrap();
    hosts.read_str(encoded, KnownHostFileKind::OpenSSH).unwrap();

    assert_eq!(hosts.iter().count(), 1);
    let host = hosts.iter().next().unwrap().unwrap();
    assert_eq!(host.name(), None);
    assert_eq!(host.key(), "\
AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9I\
DSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVD\
BfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eF\
zLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKS\
CZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2R\
PW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi\
/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==");

    assert_eq!(hosts.write_string(&host, KnownHostFileKind::OpenSSH).unwrap(),
               encoded);
    hosts.remove(host).unwrap();
}
