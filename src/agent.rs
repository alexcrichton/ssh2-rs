use std::ffi::CString;
use std::marker;
use std::slice;
use std::str;
use std::sync::Arc;

use util::Binding;
use {raw, Error, SessionInner};

/// A structure representing a connection to an SSH agent.
///
/// Agents can be used to authenticate a session.
pub struct Agent {
    raw: *mut raw::LIBSSH2_AGENT,
    sess: Arc<SessionInner>,
}

/// An iterator over the identities found in an SSH agent.
pub struct Identities<'agent> {
    prev: *mut raw::libssh2_agent_publickey,
    agent: &'agent Agent,
}

/// A public key which is extracted from an SSH agent.
pub struct PublicKey<'agent> {
    raw: *mut raw::libssh2_agent_publickey,
    _marker: marker::PhantomData<&'agent [u8]>,
}

impl Agent {
    pub(crate) fn from_raw_opt(
        raw: *mut raw::LIBSSH2_AGENT,
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

    /// Connect to an ssh-agent running on the system.
    pub fn connect(&mut self) -> Result<(), Error> {
        unsafe { self.sess.rc(raw::libssh2_agent_connect(self.raw)) }
    }

    /// Close a connection to an ssh-agent.
    pub fn disconnect(&mut self) -> Result<(), Error> {
        unsafe { self.sess.rc(raw::libssh2_agent_disconnect(self.raw)) }
    }

    /// Request an ssh-agent to list of public keys, and stores them in the
    /// internal collection of the handle.
    ///
    /// Call `identities` to get the public keys.
    pub fn list_identities(&mut self) -> Result<(), Error> {
        unsafe { self.sess.rc(raw::libssh2_agent_list_identities(self.raw)) }
    }

    /// Get an iterator over the identities of this agent.
    pub fn identities(&self) -> Identities {
        Identities {
            prev: 0 as *mut _,
            agent: self,
        }
    }

    /// Attempt public key authentication with the help of ssh-agent.
    pub fn userauth(&self, username: &str, identity: &PublicKey) -> Result<(), Error> {
        let username = CString::new(username)?;
        unsafe {
            self.sess.rc(raw::libssh2_agent_userauth(
                self.raw,
                username.as_ptr(),
                identity.raw,
            ))
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        unsafe { raw::libssh2_agent_free(self.raw) }
    }
}

impl<'agent> Iterator for Identities<'agent> {
    type Item = Result<PublicKey<'agent>, Error>;
    fn next(&mut self) -> Option<Result<PublicKey<'agent>, Error>> {
        unsafe {
            let mut next = 0 as *mut _;
            match raw::libssh2_agent_get_identity(self.agent.raw, &mut next, self.prev) {
                0 => {
                    self.prev = next;
                    Some(Ok(Binding::from_raw(next)))
                }
                1 => None,
                rc => Some(Err(self.agent.sess.rc(rc).err().unwrap())),
            }
        }
    }
}

impl<'agent> PublicKey<'agent> {
    /// Return the data of this public key.
    pub fn blob(&self) -> &[u8] {
        unsafe { slice::from_raw_parts_mut((*self.raw).blob, (*self.raw).blob_len as usize) }
    }

    /// Returns the comment in a printable format
    pub fn comment(&self) -> &str {
        unsafe { str::from_utf8(::opt_bytes(self, (*self.raw).comment).unwrap()).unwrap() }
    }
}

impl<'agent> Binding for PublicKey<'agent> {
    type Raw = *mut raw::libssh2_agent_publickey;

    unsafe fn from_raw(raw: *mut raw::libssh2_agent_publickey) -> PublicKey<'agent> {
        PublicKey {
            raw: raw,
            _marker: marker::PhantomData,
        }
    }

    fn raw(&self) -> *mut raw::libssh2_agent_publickey {
        self.raw
    }
}
