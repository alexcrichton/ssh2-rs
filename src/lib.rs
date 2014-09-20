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
//! // Almost all APIs require a `Session` to be available
//! let sess = Session::new().unwrap();
//! let mut agent = sess.agent().unwrap();
//!
//! // Try to authenticate with the first identity in the agent.
//! agent.connect().unwrap();
//! agent.list_identities().unwrap();
//! let identity = agent.identities().next().unwrap().unwrap();
//! agent.userauth("foo", &identity).unwrap();
//!
//! // Make sure we succeeded
//! assert!(sess.authenticated());
//! ```

#![feature(phase, unsafe_destructor)]
#![deny(warnings, missing_doc)]

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
pub use sftp::{Sftp, OpenFlags, Read, Write, Append, Create, Truncate};
pub use sftp::{Exclusive, OpenType, OpenFile, OpenDir, File, FileStat};
pub use sftp::{RenameFlags, Atomic, Overwrite, Native};

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

#[allow(missing_doc)]
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
pub enum SessionFlag {
    /// If set, libssh2 will not attempt to block SIGPIPEs but will let them
    /// trigger from the underlying socket layer.
    SigPipe = raw::LIBSSH2_FLAG_SIGPIPE as int,

    /// If set - before the connection negotiation is performed - libssh2 will
    /// try to negotiate compression enabling for this connection. By default
    /// libssh2 will not attempt to use compression.
    Compress = raw::LIBSSH2_FLAG_COMPRESS as int,
}

#[allow(missing_doc)]
pub enum HostKeyType {
    TypeUnknown = raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN as int,
    TypeRsa = raw::LIBSSH2_HOSTKEY_TYPE_RSA as int,
    TypeDss = raw::LIBSSH2_HOSTKEY_TYPE_DSS as int,
}

#[allow(missing_doc)]
pub enum MethodType {
    MethodKex = raw::LIBSSH2_METHOD_KEX as int,
    MethodHostKey = raw::LIBSSH2_METHOD_HOSTKEY as int,
    MethodCryptCs = raw::LIBSSH2_METHOD_CRYPT_CS as int,
    MethodCryptSc = raw::LIBSSH2_METHOD_CRYPT_SC as int,
    MethodMacCs = raw::LIBSSH2_METHOD_MAC_CS as int,
    MethodMacSc = raw::LIBSSH2_METHOD_MAC_SC as int,
    MethodCompCs = raw::LIBSSH2_METHOD_COMP_CS as int,
    MethodCompSc = raw::LIBSSH2_METHOD_COMP_SC as int,
    MethodLangCs = raw::LIBSSH2_METHOD_LANG_CS as int,
    MethodLangSc = raw::LIBSSH2_METHOD_LANG_SC as int,
}

/// When passed to `Channel::flush_stream`, flushes all extended data
/// substreams.
pub static FlushExtendedData: uint = -1;
/// When passed to `Channel::flush_stream`, flushes all substream.
pub static FlushAll: uint = -2;
/// Stream ID of the stderr channel for stream-related methods on `Channel`
pub static ExtendedDataStderr: uint = 1;

#[allow(missing_doc)]
pub enum HashType {
    HashMd5 = raw::LIBSSH2_HOSTKEY_HASH_MD5 as int,
    HashSha1 = raw:: LIBSSH2_HOSTKEY_HASH_SHA1 as int,
}

#[allow(missing_doc)]
pub enum KnownHostFileKind {
    OpenSSH = raw::LIBSSH2_KNOWNHOST_FILE_OPENSSH as int,
}

/// Possible results of a call to `KnownHosts::check`
pub enum CheckResult {
    /// Hosts and keys match
    CheckMatch = raw::LIBSSH2_KNOWNHOST_CHECK_MATCH as int,
    /// Host was found, but the keys didn't match!
    CheckMismatch = raw::LIBSSH2_KNOWNHOST_CHECK_MISMATCH as int,
    /// No host match was found
    CheckNotFound = raw::LIBSSH2_KNOWNHOST_CHECK_NOTFOUND as int,
    /// Something prevented the check to be made
    CheckFailure = raw::LIBSSH2_KNOWNHOST_CHECK_FAILURE as int,
}

#[allow(missing_doc)]
pub enum KnownHostKeyFormat {
    KeyRsa1 = raw::LIBSSH2_KNOWNHOST_KEY_RSA1 as int,
    KeySshRsa = raw::LIBSSH2_KNOWNHOST_KEY_SSHRSA as int,
    KeySshDss = raw::LIBSSH2_KNOWNHOST_KEY_SSHDSS as int,
}
