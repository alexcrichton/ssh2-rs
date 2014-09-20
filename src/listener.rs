use std::kinds::marker;

use {raw, Session, Error, Channel};

/// A listener represents a forwarding port from the remote server.
///
/// New channels can be accepted from a listener which represent connections on
/// the remote server's port.
pub struct Listener<'a> {
    raw: *mut raw::LIBSSH2_LISTENER,
    sess: &'a Session,
    marker: marker::NoSync,
}

impl<'a> Listener<'a> {
    /// Wraps a raw pointer in a new Listener structure tied to the lifetime of the
    /// given session.
    ///
    /// This consumes ownership of `raw`.
    pub unsafe fn from_raw(sess: &Session,
                           raw: *mut raw::LIBSSH2_LISTENER) -> Listener {
        Listener {
            raw: raw,
            sess: sess,
            marker: marker::NoSync,
        }
    }

    /// Accept a queued connection from this listener.
    pub fn accept(&mut self) -> Result<Channel<'a>, Error> {
        unsafe {
            let ret = raw::libssh2_channel_forward_accept(self.raw);
            if ret.is_null() {
                Err(Error::last_error(self.sess).unwrap())
            } else {
                Ok(Channel::from_raw(self.sess, ret))
            }
        }
    }
}

#[unsafe_destructor]
impl<'a> Drop for Listener<'a> {
    fn drop(&mut self) {
        unsafe { assert_eq!(raw::libssh2_channel_forward_cancel(self.raw), 0) }
    }
}

