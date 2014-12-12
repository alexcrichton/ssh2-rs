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
//!     println!("{}", identity.comment())
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

#![feature(phase, unsafe_destructor)]
#![deny(warnings, missing_docs)]

extern crate "libssh2-sys" as raw;
extern crate libc;

use std::c_str::CString;
use std::mem;
use std::rt;
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
    static mut INIT: Once = ONCE_INIT;
    unsafe {
        INIT.doit(|| {
            assert_eq!(raw::libssh2_init(0), 0);
            rt::at_exit(proc() {
                raw::libssh2_exit();
            });
        })
    }
}

unsafe fn opt_bytes<'a, T>(_: &'a T,
                           c: *const libc::c_char) -> Option<&'a [u8]> {
    if c.is_null() {
        None
    } else {
        let s = CString::new(c, false);
        Some(mem::transmute(s.as_bytes_no_nul()))
    }
}

#[allow(missing_docs)]
#[deriving(Copy)]
pub enum DisconnectCode {
    HostNotAllowedToConnect =
        raw::SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT as int,
    ProtocolError = raw::SSH_DISCONNECT_PROTOCOL_ERROR as int,
    KeyExchangeFailed = raw::SSH_DISCONNECT_KEY_EXCHANGE_FAILED as int,
    Reserved = raw::SSH_DISCONNECT_RESERVED as int,
    MacError = raw::SSH_DISCONNECT_MAC_ERROR as int,
    CompressionError = raw::SSH_DISCONNECT_COMPRESSION_ERROR as int,
    ServiceNotAvailable = raw::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE as int,
    ProtocolVersionNotSupported =
        raw::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED as int,
    HostKeyNotVerifiable = raw::SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE as int,
    ConnectionLost = raw::SSH_DISCONNECT_CONNECTION_LOST as int,
    ByApplication = raw::SSH_DISCONNECT_BY_APPLICATION as int,
    TooManyConnections = raw::SSH_DISCONNECT_TOO_MANY_CONNECTIONS as int,
    AuthCancelledByUser = raw::SSH_DISCONNECT_AUTH_CANCELLED_BY_USER as int,
    NoMoreAuthMethodsAvailable =
        raw::SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE as int,
    IllegalUserName = raw::SSH_DISCONNECT_ILLEGAL_USER_NAME as int,
}

/// Flags to be enabled/disabled on a Session
#[deriving(Copy)]
pub enum SessionFlag {
    /// If set, libssh2 will not attempt to block SIGPIPEs but will let them
    /// trigger from the underlying socket layer.
    SigPipe = raw::LIBSSH2_FLAG_SIGPIPE as int,

    /// If set - before the connection negotiation is performed - libssh2 will
    /// try to negotiate compression enabling for this connection. By default
    /// libssh2 will not attempt to use compression.
    Compress = raw::LIBSSH2_FLAG_COMPRESS as int,
}

#[allow(missing_docs)]
#[deriving(Copy)]
pub enum HostKeyType {
    Unknown = raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN as int,
    Rsa = raw::LIBSSH2_HOSTKEY_TYPE_RSA as int,
    Dss = raw::LIBSSH2_HOSTKEY_TYPE_DSS as int,
}

#[allow(missing_docs)]
#[deriving(Copy)]
pub enum MethodType {
    Kex = raw::LIBSSH2_METHOD_KEX as int,
    HostKey = raw::LIBSSH2_METHOD_HOSTKEY as int,
    CryptCs = raw::LIBSSH2_METHOD_CRYPT_CS as int,
    CryptSc = raw::LIBSSH2_METHOD_CRYPT_SC as int,
    MacCs = raw::LIBSSH2_METHOD_MAC_CS as int,
    MacSc = raw::LIBSSH2_METHOD_MAC_SC as int,
    CompCs = raw::LIBSSH2_METHOD_COMP_CS as int,
    CompSc = raw::LIBSSH2_METHOD_COMP_SC as int,
    LangCs = raw::LIBSSH2_METHOD_LANG_CS as int,
    LangSc = raw::LIBSSH2_METHOD_LANG_SC as int,
}

/// When passed to `Channel::flush_stream`, flushes all extended data
/// substreams.
pub static FLUSH_EXTENDED_DATA: uint = -1;
/// When passed to `Channel::flush_stream`, flushes all substream.
pub static FLUSH_ALL: uint = -2;
/// Stream ID of the stderr channel for stream-related methods on `Channel`
pub static EXTENDED_DATA_STDERR: uint = 1;

#[allow(missing_docs)]
#[deriving(Copy)]
pub enum HashType {
    Md5 = raw::LIBSSH2_HOSTKEY_HASH_MD5 as int,
    Sha1 = raw:: LIBSSH2_HOSTKEY_HASH_SHA1 as int,
}

#[allow(missing_docs)]
#[deriving(Copy)]
pub enum KnownHostFileKind {
    OpenSSH = raw::LIBSSH2_KNOWNHOST_FILE_OPENSSH as int,
}

/// Possible results of a call to `KnownHosts::check`
#[deriving(Copy)]
pub enum CheckResult {
    /// Hosts and keys match
    Match = raw::LIBSSH2_KNOWNHOST_CHECK_MATCH as int,
    /// Host was found, but the keys didn't match!
    Mismatch = raw::LIBSSH2_KNOWNHOST_CHECK_MISMATCH as int,
    /// No host match was found
    NotFound = raw::LIBSSH2_KNOWNHOST_CHECK_NOTFOUND as int,
    /// Something prevented the check to be made
    Failure = raw::LIBSSH2_KNOWNHOST_CHECK_FAILURE as int,
}

#[allow(missing_docs)]
#[deriving(Copy)]
pub enum KnownHostKeyFormat {
    Rsa1 = raw::LIBSSH2_KNOWNHOST_KEY_RSA1 as int,
    SshRsa = raw::LIBSSH2_KNOWNHOST_KEY_SSHRSA as int,
    SshDss = raw::LIBSSH2_KNOWNHOST_KEY_SSHDSS as int,
}
