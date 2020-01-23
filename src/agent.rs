use parking_lot::{Mutex, MutexGuard};
use std::ffi::{CStr, CString};
use std::slice;
use std::str;
use std::sync::Arc;

use {raw, Error, SessionInner};

/// A structure representing a connection to an SSH agent.
///
/// Agents can be used to authenticate a session.
pub struct Agent {
    raw: *mut raw::LIBSSH2_AGENT,
    sess: Arc<Mutex<SessionInner>>,
}

// Agent is both Send and Sync; the compiler can't see it because it
// is pessimistic about the raw pointer.  We use Arc/Mutex to guard accessing
// the raw pointer so we are safe for both.
unsafe impl Send for Agent {}
unsafe impl Sync for Agent {}

/// A public key which is extracted from an SSH agent.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    blob: Vec<u8>,
    comment: String,
}

impl Agent {
    pub(crate) fn from_raw_opt(
        raw: *mut raw::LIBSSH2_AGENT,
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

    /// Connect to an ssh-agent running on the system.
    pub fn connect(&mut self) -> Result<(), Error> {
        let sess = self.sess.lock();
        unsafe { sess.rc(raw::libssh2_agent_connect(self.raw)) }
    }

    /// Close a connection to an ssh-agent.
    pub fn disconnect(&mut self) -> Result<(), Error> {
        let sess = self.sess.lock();
        unsafe { sess.rc(raw::libssh2_agent_disconnect(self.raw)) }
    }

    /// Request an ssh-agent to list of public keys, and stores them in the
    /// internal collection of the handle.
    ///
    /// Call `identities` to get the public keys.
    pub fn list_identities(&mut self) -> Result<(), Error> {
        let sess = self.sess.lock();
        unsafe { sess.rc(raw::libssh2_agent_list_identities(self.raw)) }
    }

    /// Get list of the identities of this agent.
    pub fn identities(&self) -> Result<Vec<PublicKey>, Error> {
        let sess = self.sess.lock();
        let mut res = vec![];
        let mut prev = 0 as *mut _;
        let mut next = 0 as *mut _;
        loop {
            match unsafe { raw::libssh2_agent_get_identity(self.raw, &mut next, prev) } {
                0 => {
                    prev = next;
                    res.push(unsafe { PublicKey::from_raw(next) });
                }
                1 => break,
                rc => return Err(Error::from_session_error_raw(sess.raw, rc)),
            }
        }
        Ok(res)
    }

    fn resolve_raw_identity(
        &self,
        sess: &MutexGuard<SessionInner>,
        identity: &PublicKey,
    ) -> Result<Option<*mut raw::libssh2_agent_publickey>, Error> {
        let mut prev = 0 as *mut _;
        let mut next = 0 as *mut _;
        loop {
            match unsafe { raw::libssh2_agent_get_identity(self.raw, &mut next, prev) } {
                0 => {
                    prev = next;
                    let this_ident = unsafe { PublicKey::from_raw(next) };
                    if this_ident == *identity {
                        return Ok(Some(next));
                    }
                }
                1 => break,
                rc => return Err(Error::from_session_error_raw(sess.raw, rc)),
            }
        }
        Ok(None)
    }

    /// Attempt public key authentication with the help of ssh-agent.
    pub fn userauth(&self, username: &str, identity: &PublicKey) -> Result<(), Error> {
        let username = CString::new(username)?;
        let sess = self.sess.lock();
        let raw_ident = self
            .resolve_raw_identity(&sess, identity)?
            .ok_or_else(|| Error::new(raw::LIBSSH2_ERROR_BAD_USE, "Identity not found in agent"))?;
        unsafe {
            sess.rc(raw::libssh2_agent_userauth(
                self.raw,
                username.as_ptr(),
                raw_ident,
            ))
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        unsafe { raw::libssh2_agent_free(self.raw) }
    }
}

impl PublicKey {
    unsafe fn from_raw(raw: *mut raw::libssh2_agent_publickey) -> Self {
        let blob = slice::from_raw_parts_mut((*raw).blob, (*raw).blob_len as usize);
        let comment = (*raw).comment;
        let comment = if comment.is_null() {
            String::new()
        } else {
            CStr::from_ptr(comment).to_string_lossy().into_owned()
        };
        Self {
            blob: blob.to_vec(),
            comment,
        }
    }

    /// Return the data of this public key.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// Returns the comment in a printable format
    pub fn comment(&self) -> &str {
        &self.comment
    }
}
