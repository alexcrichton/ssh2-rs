//! Rust bindings to libssh2, an SSH client library.
//!
//! This library intends to provide a safe interface to the libssh2 library. It
//! will build the library if it's not available on the local system, and
//! otherwise link to an installed copy.
//!
//! Note that libssh2 only supports SSH *clients*, not SSH *servers*.
//! Additionally it only supports protocol v2, not protocol v1.
//!
//! # Examples
//!
//! ## Inspecting ssh-agent
//!
//! ```
//! use ssh2::Session;
//!
//! // Almost all APIs require a `Session` to be available
//! let sess = Session::new().unwrap();
//! let mut agent = sess.agent().unwrap();
//!
//! // Connect the agent and request a list of identities
//! agent.connect().unwrap();
//! agent.list_identities().unwrap();
//!
//! for identity in agent.identities() {
//!     let identity = identity.unwrap(); // assume no I/O errors
//!     println!("{}", identity.comment());
//!     let pubkey = identity.blob();
//! }
//! ```
//!
//! ## Authenticating with ssh-agent
//!
//! ```no_run
//! use ssh2::Session;
//!
//! let sess = Session::new().unwrap();
//! // perform the handshake with a network socket
//!
//! // Try to authenticate with the first identity in the agent.
//! let mut agent = sess.agent().unwrap();
//! agent.connect().unwrap();
//! agent.list_identities().unwrap();
//! let identity = agent.identities().next().unwrap().unwrap();
//! agent.userauth("foo", &identity).unwrap();
//!
//! // Make sure we succeeded
//! assert!(sess.authenticated());
//! ```
//!
//! ## Authenticating with a password
//!
//! ```no_run
//! use ssh2::Session;
//!
//! let sess = Session::new().unwrap();
//! // perform the handshake with a network socket
//!
//! sess.userauth_password("username", "password").unwrap();
//! assert!(sess.authenticated());
//! ```
//!
//! ## Upload a file
//!
//! ```no_run
//! use std::io;
//! use ssh2::Session;
//!
//! let sess = Session::new().unwrap();
//! // perform a handshake and authenticate the session
//!
//! let mut remote_file = sess.scp_send(&Path::new("remote"),
//!                                     io::USER_FILE, 10, None).unwrap();
//! remote_file.write(b"1234567890").unwrap();
//! ```
//!
//! ## Download a file
//!
//! ```no_run
//! use ssh2::Session;
//!
//! let sess = Session::new().unwrap();
//! // perform a handshake and authenticate the session
//!
//! let (mut remote_file, stat) = sess.scp_recv(&Path::new("remote")).unwrap();
//!
//! println!("remote file size: {}", stat.size);
//! let contents = remote_file.read_to_end();
//! ```

#![feature(unsafe_destructor)]
#![deny(missing_docs)]
#![cfg_attr(test, deny(warnings))]
#![allow(unstable)]

extern crate "libssh2-sys" as raw;
extern crate libc;

use std::ffi;
use std::mem;
use std::sync::{Once, ONCE_INIT};

pub use agent::{Agent, Identities, PublicKey};
pub use channel::{Channel, ExitSignal, ReadWindow, WriteWindow};
pub use error::Error;
pub use knownhosts::{KnownHosts, Hosts, Host};
pub use listener::Listener;
pub use session::Session;
pub use sftp::{Sftp, OpenFlags, READ, WRITE, APPEND, CREATE, TRUNCATE};
pub use sftp::{EXCLUSIVE, OpenType, File, FileStat};
pub use sftp::{RenameFlags, ATOMIC, OVERWRITE, NATIVE};
pub use DisconnectCode::{HostNotAllowedToConnect, ProtocolError};
pub use DisconnectCode::{KeyExchangeFailed, Reserved, MacError, CompressionError};
pub use DisconnectCode::{ServiceNotAvailable, ProtocolVersionNotSupported};
pub use DisconnectCode::{HostKeyNotVerifiable, ConnectionLost, ByApplication};
pub use DisconnectCode::{TooManyConnections, AuthCancelledByUser};
pub use DisconnectCode::{NoMoreAuthMethodsAvailable, IllegalUserName};

mod agent;
mod channel;
mod error;
mod knownhosts;
mod listener;
mod session;
mod sftp;

/// Initialize the libssh2 library.
///
/// This is optional, it is lazily invoked.
pub fn init() {
    static INIT: Once = ONCE_INIT;
    INIT.call_once(|| unsafe {
        assert_eq!(raw::libssh2_init(0), 0);
        assert_eq!(libc::atexit(shutdown), 0);
    });
    extern fn shutdown() { unsafe { raw::libssh2_exit(); } }
}

unsafe fn opt_bytes<'a, T>(_: &'a T,
                           c: *const libc::c_char) -> Option<&'a [u8]> {
    if c.is_null() {
        None
    } else {
        let s = ffi::c_str_to_bytes(&c);
        Some(mem::transmute(s))
    }
}

#[allow(missing_docs)]
#[derive(Copy)]
pub enum DisconnectCode {
    HostNotAllowedToConnect =
        raw::SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT as isize,
    ProtocolError = raw::SSH_DISCONNECT_PROTOCOL_ERROR as isize,
    KeyExchangeFailed = raw::SSH_DISCONNECT_KEY_EXCHANGE_FAILED as isize,
    Reserved = raw::SSH_DISCONNECT_RESERVED as isize,
    MacError = raw::SSH_DISCONNECT_MAC_ERROR as isize,
    CompressionError = raw::SSH_DISCONNECT_COMPRESSION_ERROR as isize,
    ServiceNotAvailable = raw::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE as isize,
    ProtocolVersionNotSupported =
        raw::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED as isize,
    HostKeyNotVerifiable = raw::SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE as isize,
    ConnectionLost = raw::SSH_DISCONNECT_CONNECTION_LOST as isize,
    ByApplication = raw::SSH_DISCONNECT_BY_APPLICATION as isize,
    TooManyConnections = raw::SSH_DISCONNECT_TOO_MANY_CONNECTIONS as isize,
    AuthCancelledByUser = raw::SSH_DISCONNECT_AUTH_CANCELLED_BY_USER as isize,
    NoMoreAuthMethodsAvailable =
        raw::SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE as isize,
    IllegalUserName = raw::SSH_DISCONNECT_ILLEGAL_USER_NAME as isize,
}

/// Flags to be enabled/disabled on a Session
#[derive(Copy)]
pub enum SessionFlag {
    /// If set, libssh2 will not attempt to block SIGPIPEs but will let them
    /// trigger from the underlying socket layer.
    SigPipe = raw::LIBSSH2_FLAG_SIGPIPE as isize,

    /// If set - before the connection negotiation is performed - libssh2 will
    /// try to negotiate compression enabling for this connection. By default
    /// libssh2 will not attempt to use compression.
    Compress = raw::LIBSSH2_FLAG_COMPRESS as isize,
}

#[allow(missing_docs)]
#[derive(Copy)]
pub enum HostKeyType {
    Unknown = raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN as isize,
    Rsa = raw::LIBSSH2_HOSTKEY_TYPE_RSA as isize,
    Dss = raw::LIBSSH2_HOSTKEY_TYPE_DSS as isize,
}

#[allow(missing_docs)]
#[derive(Copy)]
pub enum MethodType {
    Kex = raw::LIBSSH2_METHOD_KEX as isize,
    HostKey = raw::LIBSSH2_METHOD_HOSTKEY as isize,
    CryptCs = raw::LIBSSH2_METHOD_CRYPT_CS as isize,
    CryptSc = raw::LIBSSH2_METHOD_CRYPT_SC as isize,
    MacCs = raw::LIBSSH2_METHOD_MAC_CS as isize,
    MacSc = raw::LIBSSH2_METHOD_MAC_SC as isize,
    CompCs = raw::LIBSSH2_METHOD_COMP_CS as isize,
    CompSc = raw::LIBSSH2_METHOD_COMP_SC as isize,
    LangCs = raw::LIBSSH2_METHOD_LANG_CS as isize,
    LangSc = raw::LIBSSH2_METHOD_LANG_SC as isize,
}

/// When passed to `Channel::flush_stream`, flushes all extended data
/// substreams.
pub static FLUSH_EXTENDED_DATA: i32 = -1;
/// When passed to `Channel::flush_stream`, flushes all substream.
pub static FLUSH_ALL: i32 = -2;
/// Stream ID of the stderr channel for stream-related methods on `Channel`
pub static EXTENDED_DATA_STDERR: i32 = 1;

#[allow(missing_docs)]
#[derive(Copy)]
pub enum HashType {
    Md5 = raw::LIBSSH2_HOSTKEY_HASH_MD5 as isize,
    Sha1 = raw:: LIBSSH2_HOSTKEY_HASH_SHA1 as isize,
}

#[allow(missing_docs)]
#[derive(Copy)]
pub enum KnownHostFileKind {
    OpenSSH = raw::LIBSSH2_KNOWNHOST_FILE_OPENSSH as isize,
}

/// Possible results of a call to `KnownHosts::check`
#[derive(Copy)]
pub enum CheckResult {
    /// Hosts and keys match
    Match = raw::LIBSSH2_KNOWNHOST_CHECK_MATCH as isize,
    /// Host was found, but the keys didn't match!
    Mismatch = raw::LIBSSH2_KNOWNHOST_CHECK_MISMATCH as isize,
    /// No host match was found
    NotFound = raw::LIBSSH2_KNOWNHOST_CHECK_NOTFOUND as isize,
    /// Something prevented the check to be made
    Failure = raw::LIBSSH2_KNOWNHOST_CHECK_FAILURE as isize,
}

#[allow(missing_docs)]
#[derive(Copy)]
pub enum KnownHostKeyFormat {
    Rsa1 = raw::LIBSSH2_KNOWNHOST_KEY_RSA1 as isize,
    SshRsa = raw::LIBSSH2_KNOWNHOST_KEY_SSHRSA as isize,
    SshDss = raw::LIBSSH2_KNOWNHOST_KEY_SSHDSS as isize,
}
