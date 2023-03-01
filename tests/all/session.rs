use std::env;
use std::fs::File;
use std::io::{self, prelude::*};
use std::path::Path;
use tempfile::TempDir;

use ssh2::{BlockDirections, HashType, KeyboardInteractivePrompt, MethodType, Prompt, Session};

#[test]
fn session_is_send() {
    fn must_be_send<T: Send>(_: &T) -> bool {
        true
    }

    let sess = Session::new().unwrap();
    assert!(must_be_send(&sess));
}

#[test]
fn smoke() {
    let sess = Session::new().unwrap();
    assert!(sess.banner_bytes().is_none());
    sess.set_banner("foo").unwrap();
    assert!(sess.is_blocking());
    assert_eq!(sess.timeout(), 0);
    sess.set_compress(true);
    assert!(sess.host_key().is_none());
    sess.method_pref(MethodType::Kex, "diffie-hellman-group14-sha1")
        .unwrap();
    assert!(sess.methods(MethodType::Kex).is_none());
    sess.set_blocking(true);
    sess.set_timeout(0);
    sess.supported_algs(MethodType::Kex).unwrap();
    sess.supported_algs(MethodType::HostKey).unwrap();
    sess.channel_session().err().unwrap();
}

#[test]
fn smoke_handshake() {
    let user = env::var("USER").unwrap();
    let socket = ::socket();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(socket);
    sess.handshake().unwrap();
    sess.host_key().unwrap();
    let methods = sess.auth_methods(&user).unwrap();
    assert!(methods.contains("publickey"), "{}", methods);
    assert!(!sess.authenticated());

    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();
    {
        let identity = &agent.identities().unwrap()[0];
        agent.userauth(&user, &identity).unwrap();
    }
    assert!(sess.authenticated());
    sess.host_key_hash(HashType::Md5).unwrap();
}

#[test]
fn keyboard_interactive() {
    let user = env::var("USER").unwrap();
    let socket = ::socket();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(socket);
    sess.handshake().unwrap();
    sess.host_key().unwrap();
    let methods = sess.auth_methods(&user).unwrap();
    assert!(
        methods.contains("keyboard-interactive"),
        "test server ({}) must support `ChallengeResponseAuthentication yes`, not just {}",
        ::test_addr(),
        methods
    );
    assert!(!sess.authenticated());

    // We don't know the correct response for whatever challenges
    // will be returned to us, but that's ok; the purpose of this
    // test is to check that we have some basically sane interaction
    // with the library.

    struct Prompter {
        some_data: usize,
    }

    impl KeyboardInteractivePrompt for Prompter {
        fn prompt<'a>(
            &mut self,
            username: &str,
            instructions: &str,
            prompts: &[Prompt<'a>],
        ) -> Vec<String> {
            // Sanity check that the pointer manipulation resolves and
            // we read back our member data ok
            assert_eq!(self.some_data, 42);

            eprintln!("username: {}", username);
            eprintln!("instructions: {}", instructions);
            eprintln!("prompts: {:?}", prompts);

            // Unfortunately, we can't make any assertions about username
            // or instructions, as they can be empty (on my linux system)
            // or may have arbitrary contents
            // assert_eq!(username, env::var("USER").unwrap());
            // assert!(!instructions.is_empty());

            // Hopefully this isn't too brittle an assertion
            if prompts.len() == 1 {
                assert_eq!(prompts.len(), 1);
                // Might be "Password: " or "Password:" or other variations
                assert!(prompts[0].text.contains("sword"));
                assert_eq!(prompts[0].echo, false);
            } else {
                // maybe there's some PAM configuration that results
                // in multiple prompts. We can't make any real assertions
                // in this case, other than that there has to be at least
                // one prompt.
                assert!(!prompts.is_empty());
            }

            prompts.iter().map(|_| "bogus".to_string()).collect()
        }
    }

    let mut p = Prompter { some_data: 42 };

    match sess.userauth_keyboard_interactive(&user, &mut p) {
        Ok(_) => eprintln!("auth succeeded somehow(!)"),
        Err(err) => eprintln!("auth failed as expected: {}", err),
    };

    // The only way this assertion will be false is if the person
    // running these tests has "bogus" as their password
    assert!(!sess.authenticated());
}

#[test]
fn keepalive() {
    let sess = ::authed_session();
    sess.set_keepalive(false, 10);
    sess.keepalive_send().unwrap();
}

#[test]
fn scp_recv() {
    let sess = ::authed_session();

    // Download our own source file; it's the only path that
    // we know for sure exists on this system.
    let p = Path::new(file!()).canonicalize().unwrap();

    let (mut ch, _) = sess.scp_recv(&p).unwrap();
    let mut data = String::new();
    ch.read_to_string(&mut data).unwrap();
    let mut expected = String::new();
    File::open(&p)
        .unwrap()
        .read_to_string(&mut expected)
        .unwrap();
    assert!(data == expected);
}

#[test]
fn scp_send() {
    let td = TempDir::new().unwrap();
    let sess = ::authed_session();
    let mut ch = sess
        .scp_send(&td.path().join("foo"), 0o644, 6, None)
        .unwrap();
    ch.write_all(b"foobar").unwrap();
    drop(ch);
    let mut actual = Vec::new();
    File::open(&td.path().join("foo"))
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, b"foobar");
}

#[test]
fn block_directions() {
    let mut sess = ::authed_session();
    sess.set_blocking(false);
    let actual = sess.handshake().map_err(|e| io::Error::from(e).kind());
    assert_eq!(actual, Err(io::ErrorKind::WouldBlock));
    assert_eq!(sess.block_directions(), BlockDirections::Inbound);
}
