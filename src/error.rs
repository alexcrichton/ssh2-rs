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

    /// Get the message corresponding to this error
    pub fn message(&self) -> &str { self.msg }
}

impl fmt::Show for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.msg)
    }
}
