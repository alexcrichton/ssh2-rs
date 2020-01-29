use libc;
use std::borrow::Cow;
use std::error;
use std::ffi::NulError;
use std::fmt;
use std::io;
use std::ptr::null_mut;
use std::str;

use {raw, Session};

/// Representation of an error that can occur within libssh2
#[derive(Debug)]
#[allow(missing_copy_implementations)]
pub struct Error {
    code: libc::c_int,
    msg: Cow<'static, str>,
}

impl Error {
    #[doc(hidden)]
    pub fn last_error_raw(raw: *mut raw::LIBSSH2_SESSION) -> Option<Error> {
        unsafe {
            let mut msg = null_mut();
            let rc = raw::libssh2_session_last_error(raw, &mut msg, null_mut(), 0);
            if rc == 0 {
                return None;
            }

            // The pointer stored in `msg` points to the internal buffer of
            // LIBSSH2_SESSION, so the error message should be copied before
            // it is overwritten by the next API call.
            Some(Self {
                code: rc,
                msg: make_error_message(msg),
            })
        }
    }

    /// Given a libssh2 error return code, generate an Error object that
    /// encapsulates that error code and the error reason.
    /// The error reason is extracted from the Session and is used if the
    /// session contains the same error code as that provided.
    /// If the error code doesn't match then an approximation of the error
    /// reason is used instead of the error message stored in the Session.
    pub fn from_session_error(sess: &Session, rc: libc::c_int) -> Error {
        Self::from_session_error_raw(&mut *sess.raw(), rc)
    }

    #[doc(hidden)]
    pub fn from_session_error_raw(raw: *mut raw::LIBSSH2_SESSION, rc: libc::c_int) -> Error {
        unsafe {
            let mut msg = null_mut();
            let res = raw::libssh2_session_last_error(raw, &mut msg, null_mut(), 0);
            if res != rc {
                return Self::from_errno(rc);
            }

            // The pointer stored in `msg` points to the internal buffer of
            // LIBSSH2_SESSION, so the error message should be copied before
            // it is overwritten by the next API call.
            Self {
                code: rc,
                msg: make_error_message(msg),
            }
        }
    }

    /// Generate the last error that occurred for a `Session`.
    ///
    /// Returns `None` if there was no last error.
    pub fn last_error(sess: &Session) -> Option<Error> {
        Self::last_error_raw(&mut *sess.raw())
    }

    /// Create a new error for the given code and message
    pub fn new(code: libc::c_int, msg: &'static str) -> Error {
        Error {
            code: code,
            msg: Cow::Borrowed(msg),
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

    pub(crate) fn rc(rc: libc::c_int) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else {
            Err(Self::from_errno(rc))
        }
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
            _ => "unknown error",
        };
        Error::new(code, msg)
    }

    /// Get the message corresponding to this error
    pub fn message(&self) -> &str {
        &*self.msg
    }

    /// Return the code for this error
    pub fn code(&self) -> libc::c_int {
        self.code
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        let kind = match err.code {
            raw::LIBSSH2_ERROR_EAGAIN => io::ErrorKind::WouldBlock,
            raw::LIBSSH2_ERROR_TIMEOUT => io::ErrorKind::TimedOut,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, err.msg)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.msg)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        self.message()
    }
}

impl From<NulError> for Error {
    fn from(_: NulError) -> Error {
        Error::new(
            raw::LIBSSH2_ERROR_INVAL,
            "provided data contained a nul byte and could not be used \
             as as string",
        )
    }
}

unsafe fn make_error_message(msg: *mut libc::c_char) -> Cow<'static, str> {
    const FALLBACK: Cow<'_, str> = Cow::Borrowed("<failed to fetch the error message>");
    ::opt_bytes(&(), msg)
        .and_then(|msg| {
            str::from_utf8(msg)
                .map(|msg| Cow::Owned(msg.to_owned()))
                .ok()
        })
        .unwrap_or_else(|| FALLBACK)
}
