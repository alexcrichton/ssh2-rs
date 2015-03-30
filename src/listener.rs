use {raw, Session, Error, Channel};
use util::SessionBinding;

/// A listener represents a forwarding port from the remote server.
///
/// New channels can be accepted from a listener which represent connections on
/// the remote server's port.
pub struct Listener<'sess> {
    raw: *mut raw::LIBSSH2_LISTENER,
    sess: &'sess Session,
}

impl<'sess> Listener<'sess> {
    /// Accept a queued connection from this listener.
    pub fn accept(&mut self) -> Result<Channel<'sess>, Error> {
        unsafe {
            let ret = raw::libssh2_channel_forward_accept(self.raw);
            SessionBinding::from_raw_opt(self.sess, ret)
        }
    }
}

impl<'sess> SessionBinding<'sess> for Listener<'sess> {
    type Raw = raw::LIBSSH2_LISTENER;

    unsafe fn from_raw(sess: &'sess Session,
                       raw: *mut raw::LIBSSH2_LISTENER) -> Listener<'sess> {
        Listener {
            raw: raw,
            sess: sess,
        }
    }
    fn raw(&self) -> *mut raw::LIBSSH2_LISTENER { self.raw }
}

impl<'sess> Drop for Listener<'sess> {
    fn drop(&mut self) {
        unsafe {
            let _ = raw::libssh2_channel_forward_cancel(self.raw);
        }
    }
}

