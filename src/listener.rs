use parking_lot::Mutex;
use std::sync::Arc;
use {raw, Channel, Error, SessionInner};

/// A listener represents a forwarding port from the remote server.
///
/// New channels can be accepted from a listener which represent connections on
/// the remote server's port.
pub struct Listener {
    raw: *mut raw::LIBSSH2_LISTENER,
    sess: Arc<Mutex<SessionInner>>,
}

// Listener is both Send and Sync; the compiler can't see it because it
// is pessimistic about the raw pointer.  We use Arc/Mutex to guard accessing
// the raw pointer so we are safe for both.
unsafe impl Send for Listener {}
unsafe impl Sync for Listener {}

impl Listener {
    /// Accept a queued connection from this listener.
    pub fn accept(&mut self) -> Result<Channel, Error> {
        let sess = self.sess.lock();
        unsafe {
            let chan = raw::libssh2_channel_forward_accept(self.raw);
            let err = sess.last_error();
            Channel::from_raw_opt(chan, err, &self.sess)
        }
    }

    pub(crate) fn from_raw_opt(
        raw: *mut raw::LIBSSH2_LISTENER,
        err: Option<Error>,
        sess: &Arc<Mutex<SessionInner>>,
    ) -> Result<Self, Error> {
        if raw.is_null() {
            Err(err.unwrap_or_else(Error::unknown))
        } else {
            Ok(Self {
                raw,
                sess: Arc::clone(sess),
            })
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _sess = self.sess.lock();
        unsafe {
            let _ = raw::libssh2_channel_forward_cancel(self.raw);
        }
    }
}
