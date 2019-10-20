use std::sync::Arc;
use {raw, Channel, Error, SessionInner};

/// A listener represents a forwarding port from the remote server.
///
/// New channels can be accepted from a listener which represent connections on
/// the remote server's port.
pub struct Listener {
    raw: *mut raw::LIBSSH2_LISTENER,
    sess: Arc<SessionInner>,
}

impl Listener {
    /// Accept a queued connection from this listener.
    pub fn accept(&mut self) -> Result<Channel, Error> {
        unsafe {
            let chan = raw::libssh2_channel_forward_accept(self.raw);
            Channel::from_raw_opt(chan, &self.sess)
        }
    }

    pub(crate) fn from_raw_opt(
        raw: *mut raw::LIBSSH2_LISTENER,
        sess: &Arc<SessionInner>,
    ) -> Result<Self, Error> {
        if raw.is_null() {
            Err(Error::last_error_raw(sess.raw).unwrap_or_else(Error::unknown))
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
        unsafe {
            let _ = raw::libssh2_channel_forward_cancel(self.raw);
        }
    }
}
