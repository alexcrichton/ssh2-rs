use std::kinds::marker;
use libc::c_int;

use {raw, Session, Error};

pub struct Sftp<'a> {
    raw: *mut raw::LIBSSH2_SFTP,
    marker1: marker::NoSync,
    marker2: marker::ContravariantLifetime<'a>,
    marker3: marker::NoSend,
}

impl<'a> Sftp<'a> {
    /// Wraps a raw pointer in a new Sftp structure tied to the lifetime of the
    /// given session.
    ///
    /// This consumes ownership of `raw`.
    pub unsafe fn from_raw(_sess: &Session,
                           raw: *mut raw::LIBSSH2_SFTP) -> Sftp {
        Sftp {
            raw: raw,
            marker1: marker::NoSync,
            marker2: marker::ContravariantLifetime,
            marker3: marker::NoSend,
        }
    }

    /// Peel off the last error to happen on this SFTP instance.
    pub fn last_error(&self) -> Error {
        let code = unsafe { raw::libssh2_sftp_last_error(self.raw) };
        Error::from_errno(code as c_int)
    }
}

#[unsafe_destructor]
impl<'a> Drop for Sftp<'a> {
    fn drop(&mut self) {
        unsafe { assert_eq!(raw::libssh2_sftp_shutdown(self.raw), 0) }
    }
}


