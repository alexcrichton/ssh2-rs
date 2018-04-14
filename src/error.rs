use std::error;
use std::ffi::NulError;
use std::fmt;
use std::str;
use libc;

use {raw, Session};
use util::Binding;

/// Representation of an error that can occur within libssh2
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Error {
    code: libc::c_int,
    msg: &'static str,
}

impl Error {
    /// Generate the last error that occurred for a `Session`.
    ///
    /// Returns `None` if there was no last error.
    pub fn last_error(sess: &Session) -> Option<Error> {
        static STATIC: () = ();
        unsafe {
            let mut msg = 0 as *mut _;
            let rc = raw::libssh2_session_last_error(sess.raw(), &mut msg,
                                                     0 as *mut _, 0);
            if rc == 0 { return None }
            let s = ::opt_bytes(&STATIC, msg).unwrap();
            Some(Error::new(rc, str::from_utf8(s).unwrap()))
        }
    }

    /// Create a new error for the given code and message
    pub fn new(code: libc::c_int, msg: &'static str) -> Error {
        Error {
            code: code,
            msg: msg,
        }
    }

    /// Generate an error that represents EOF
    pub fn eof() -> Error {
        Error::new(raw::LIBSSH2_ERROR_CHANNEL_EOF_SENT, "end of file")
    }

    /// Generate an error for unknown failure
    pub fn unknown() -> Error {
        Error::new(libc::c_int::min_value(), "no other error listed")
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
            raw::LIBSSH2_FX_EOF => "end of file",
            raw::LIBSSH2_FX_NO_SUCH_FILE => "no such file",
            raw::LIBSSH2_FX_PERMISSION_DENIED => "permission denied",
            raw::LIBSSH2_FX_FAILURE => "failure",
            raw::LIBSSH2_FX_BAD_MESSAGE => "bad message",
            raw::LIBSSH2_FX_NO_CONNECTION => "no connection",
            raw::LIBSSH2_FX_CONNECTION_LOST => "connection lost",
            raw::LIBSSH2_FX_OP_UNSUPPORTED => "operation unsupported",
            raw::LIBSSH2_FX_INVALID_HANDLE => "invalid handle",
            raw::LIBSSH2_FX_NO_SUCH_PATH => "no such path",
            raw::LIBSSH2_FX_FILE_ALREADY_EXISTS => "file already exists",
            raw::LIBSSH2_FX_WRITE_PROTECT => "file is write protected",
            raw::LIBSSH2_FX_NO_MEDIA => "no media available",
            raw::LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM => "no space on filesystem",
            raw::LIBSSH2_FX_QUOTA_EXCEEDED => "quota exceeded",
            raw::LIBSSH2_FX_UNKNOWN_PRINCIPAL => "unknown principal",
            raw::LIBSSH2_FX_LOCK_CONFLICT => "lock conflict",
            raw::LIBSSH2_FX_DIR_NOT_EMPTY => "directory not empty",
            raw::LIBSSH2_FX_NOT_A_DIRECTORY => "not a directory",
            raw::LIBSSH2_FX_INVALID_FILENAME => "invalid filename",
            raw::LIBSSH2_FX_LINK_LOOP => "link loop",
            _ => "unknown error"
        };
        Error::new(code, msg)
    }

    /// Get the message corresponding to this error
    pub fn message(&self) -> &str { self.msg }

    /// Return the code for this error
    pub fn code(&self) -> libc::c_int { self.code }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.msg)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str { self.message() }
}

impl From<NulError> for Error {
    fn from(_: NulError) -> Error {
        Error::new(raw::LIBSSH2_ERROR_INVAL,
                   "provided data contained a nul byte and could not be used \
                    as as string")
    }
}
