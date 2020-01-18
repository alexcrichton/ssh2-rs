use ssh2::Session;

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();
    {
        let a = agent.identities().unwrap();
        let i1 = &a[0];
        assert!(agent.userauth("foo", &i1).is_err());
    }
    agent.disconnect().unwrap();
}
