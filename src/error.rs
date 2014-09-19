use std::fmt;
use std::kinds::marker;
use std::str;
use libc;

use {raw, Session};

/// Representation of an error that can occur within libssh2
pub struct Error {
    code: libc::c_int,
    msg: &'static str,
    marker: marker::NoCopy,
}

impl Error {
    /// Generate the last error that occurred for a `Session`.
    ///
    /// Returns `None` if there was no last error.
    pub fn last_error(sess: &Session) -> Option<Error> {
        unsafe {
            let mut msg = 0 as *mut _;
            let rc = raw::libssh2_session_last_error(sess.raw(), &mut msg,
                                                     0 as *mut _, 0);
            if rc == 0 { return None }
            Some(Error::new(rc, str::raw::c_str_to_static_slice(msg as *const _)))
        }
    }

    /// Create a new error for the given code and message
    pub fn new(code: libc::c_int, msg: &'static str) -> Error {
        Error {
            code: code,
            msg: msg,
            marker: marker::NoCopy,
        }
    }

    /// Generate an error that represents EOF
    pub fn eof() -> Error {
        Error::new(raw::LIBSSH2_ERROR_CHANNEL_EOF_SENT, "end of file")
    }

    /// Construct an error from an error code from libssh2
    pub fn from_errno(code: libc::c_int) -> Error {
        let msg = match code {
            raw::LIBSSH2_ERROR_BANNER_RECV => "banner recv failure",
            raw::LIBSSH2_ERROR_BANNER_SEND => "banner send failure",
            raw::LIBSSH2_ERROR_INVALID_MAC => "invalid mac",
            raw::LIBSSH2_ERROR_KEX_FAILURE => "kex failure",
            raw::LIBSSH2_ERROR_ALLOC => "alloc failure",
            raw::LIBSSH2_ERROR_SOCKET_SEND => "socket send faiulre",
            raw::LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE => "key exchange failure",
            raw::LIBSSH2_ERROR_TIMEOUT => "timed out",
            raw::LIBSSH2_ERROR_HOSTKEY_INIT => "hostkey init error",
            raw::LIBSSH2_ERROR_HOSTKEY_SIGN => "hostkey sign error",
            raw::LIBSSH2_ERROR_DECRYPT => "decrypt error",
            raw::LIBSSH2_ERROR_SOCKET_DISCONNECT => "socket disconnected",
            raw::LIBSSH2_ERROR_PROTO => "protocol error",
            raw::LIBSSH2_ERROR_PASSWORD_EXPIRED => "password expired",
            raw::LIBSSH2_ERROR_FILE => "file error",
            raw::LIBSSH2_ERROR_METHOD_NONE => "bad method name",
            raw::LIBSSH2_ERROR_AUTHENTICATION_FAILED => "authentication failed",
            raw::LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED => "public key unverified",
            raw::LIBSSH2_ERROR_CHANNEL_OUTOFORDER => "channel out of order",
            raw::LIBSSH2_ERROR_CHANNEL_FAILURE => "channel failure",
            raw::LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED => "request denied",
            raw::LIBSSH2_ERROR_CHANNEL_UNKNOWN => "unknown channel error",
            raw::LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED => "window exceeded",
            raw::LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED => "packet exceeded",
            raw::LIBSSH2_ERROR_CHANNEL_CLOSED => "closed channel",
            raw::LIBSSH2_ERROR_CHANNEL_EOF_SENT => "eof sent",
            raw::LIBSSH2_ERROR_SCP_PROTOCOL => "scp protocol error",
            raw::LIBSSH2_ERROR_ZLIB => "zlib error",
            raw::LIBSSH2_ERROR_SOCKET_TIMEOUT => "socket timeout",
            raw::LIBSSH2_ERROR_SFTP_PROTOCOL => "sftp protocol error",
            raw::LIBSSH2_ERROR_REQUEST_DENIED => "request denied",
            raw::LIBSSH2_ERROR_METHOD_NOT_SUPPORTED => "method not supported",
            raw::LIBSSH2_ERROR_INVAL => "invalid",
            raw::LIBSSH2_ERROR_INVALID_POLL_TYPE => "invalid poll type",
            raw::LIBSSH2_ERROR_PUBLICKEY_PROTOCOL => "public key protocol error",
            raw::LIBSSH2_ERROR_EAGAIN => "operation would block",
            raw::LIBSSH2_ERROR_BUFFER_TOO_SMALL => "buffer too small",
            raw::LIBSSH2_ERROR_BAD_USE => "bad use error",
            raw::LIBSSH2_ERROR_COMPRESS => "compression error",
            raw::LIBSSH2_ERROR_OUT_OF_BOUNDARY => "out of bounds",
            raw::LIBSSH2_ERROR_AGENT_PROTOCOL => "invalid agent protocol",
            raw::LIBSSH2_ERROR_SOCKET_RECV => "error receiving on socket",
            raw::LIBSSH2_ERROR_ENCRYPT => "bad encrypt",
            raw::LIBSSH2_ERROR_BAD_SOCKET => "bad socket",
            raw::LIBSSH2_ERROR_KNOWN_HOSTS => "known hosts error",
            _ => "unknown error"
        };
        Error::new(code, msg)
    }

    /// Get the message corresponding to this error
    pub fn message(&self) -> &str { self.msg }
}

impl fmt::Show for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.msg)
    }
}
