#![feature(phase)]

#[phase(plugin)]
extern crate "link-config" as link_config;
extern crate libc;

use std::c_str::CString;
use std::mem;
use std::rt;
use std::sync::{Once, ONCE_INIT};

pub use session::Session;
pub use error::Error;

pub mod raw;
mod session;
mod error;

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

pub enum HostKeyType {
    TypeUnknown = raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN as int,
    TypeRsa = raw::LIBSSH2_HOSTKEY_TYPE_RSA as int,
    TypeDss = raw::LIBSSH2_HOSTKEY_TYPE_DSS as int,
}

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
