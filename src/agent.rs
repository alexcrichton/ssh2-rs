use std::ffi::CString;
use std::marker;
use std::slice;
use std::str;

use {raw, Session, Error};
use util::{Binding, SessionBinding};

/// A structure representing a connection to an SSH agent.
///
/// Agents can be used to authenticate a session.
pub struct Agent<'sess> {
    raw: *mut raw::LIBSSH2_AGENT,
    sess: &'sess Session,
}

/// An iterator over the identities found in an SSH agent.
pub struct Identities<'agent> {
    prev: *mut raw::libssh2_agent_publickey,
    agent: &'agent Agent<'agent>,
}

/// A public key which is extracted from an SSH agent.
pub struct PublicKey<'agent> {
    raw: *mut raw::libssh2_agent_publickey,
    _marker: marker::PhantomData<&'agent [u8]>,
}

impl<'sess> Agent<'sess> {
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
        Identities { prev: 0 as *mut _, agent: self }
    }

    /// Attempt public key authentication with the help of ssh-agent.
    pub fn userauth(&self, username: &str, identity: &PublicKey)
                    -> Result<(), Error>{
        let username = try!(CString::new(username));
        unsafe {
            self.sess.rc(raw::libssh2_agent_userauth(self.raw,
                                                     username.as_ptr(),
                                                     identity.raw))

        }
    }
}

impl<'sess> SessionBinding<'sess> for Agent<'sess> {
    type Raw = raw::LIBSSH2_AGENT;

    unsafe fn from_raw(sess: &'sess Session,
                       raw: *mut raw::LIBSSH2_AGENT) -> Agent<'sess> {
        Agent { raw: raw, sess: sess }
    }
    fn raw(&self) -> *mut raw::LIBSSH2_AGENT { self.raw }
}

impl<'a> Drop for Agent<'a> {
    fn drop(&mut self) {
        unsafe { raw::libssh2_agent_free(self.raw) }
    }
}

impl<'agent> Iterator for Identities<'agent> {
    type Item = Result<PublicKey<'agent>, Error>;
    fn next(&mut self) -> Option<Result<PublicKey<'agent>, Error>> {
        unsafe {
            let mut next = 0 as *mut _;
            match raw::libssh2_agent_get_identity(self.agent.raw,
                                                  &mut next,
                                                  self.prev) {
                0 => { self.prev = next; Some(Ok(Binding::from_raw(next))) }
                1 => None,
                rc => Some(Err(self.agent.sess.rc(rc).err().unwrap())),
            }
        }
    }
}

impl<'agent> PublicKey<'agent> {
    /// Return the data of this public key.
    pub fn blob(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts_mut((*self.raw).blob,
                                      (*self.raw).blob_len as usize)
        }
    }

    /// Returns the comment in a printable format
    pub fn comment(&self) -> &str {
        unsafe {
            str::from_utf8(::opt_bytes(self, (*self.raw).comment).unwrap())
                .unwrap()
        }
    }
}

impl<'agent> Binding for PublicKey<'agent> {
    type Raw = *mut raw::libssh2_agent_publickey;

    unsafe fn from_raw(raw: *mut raw::libssh2_agent_publickey)
                       -> PublicKey<'agent> {
        PublicKey { raw: raw, _marker: marker::PhantomData }
    }

    fn raw(&self) -> *mut raw::libssh2_agent_publickey { self.raw }
}
