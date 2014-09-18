use ssh2::Session;

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();
    {
        let mut a = agent.identities();
        let i1 = a.next().unwrap().unwrap();
        a.count();
        assert!(agent.userauth("foo", &i1).is_err());
    }
    agent.disconnect().unwrap();
}
