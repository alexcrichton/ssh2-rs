use std::kinds::marker;
use std::mem;
use std::raw as stdraw;
use std::str;

use {raw, Session, Error};

pub struct Agent<'a> {
    raw: *mut raw::LIBSSH2_AGENT,
    sess: &'a Session,
    marker: marker::NoSync,
}

pub struct Identities<'a> {
    prev: *mut raw::libssh2_agent_publickey,
    agent: &'a Agent<'a>,
}

pub struct PublicKey<'a> {
    raw: *mut raw::libssh2_agent_publickey,
    marker1: marker::NoSync,
    marker2: marker::NoSend,
    marker3: marker::ContravariantLifetime<'a>,
    marker4: marker::NoCopy,
}

impl<'a> Agent<'a> {
    /// Wraps a raw pointer in a new Agent structure tied to the lifetime of the
    /// given session.
    ///
    /// This consumes ownership of `raw`.
    pub unsafe fn from_raw(sess: &Session,
                           raw: *mut raw::LIBSSH2_AGENT) -> Agent {
        Agent {
            raw: raw,
            sess: sess,
            marker: marker::NoSync,
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
        Identities { prev: 0 as *mut _, agent: self }
    }

    /// Attempt public key authentication with the help of ssh-agent.
    pub fn userauth(&self, username: &str, identity: &PublicKey)
                    -> Result<(), Error>{
        let username = username.to_c_str();
        unsafe {
            self.sess.rc(raw::libssh2_agent_userauth(self.raw,
                                                     username.as_ptr(),
                                                     identity.raw))

        }
    }
}

#[unsafe_destructor]
impl<'a> Drop for Agent<'a> {
    fn drop(&mut self) {
        unsafe { raw::libssh2_agent_free(self.raw) }
    }
}

impl<'a> Iterator<Result<PublicKey<'a>, Error>> for Identities<'a> {
    fn next(&mut self) -> Option<Result<PublicKey<'a>, Error>> {
        unsafe {
            let mut next = 0 as *mut _;
            match raw::libssh2_agent_get_identity(self.agent.raw,
                                                  &mut next,
                                                  self.prev) {
                0 => { self.prev = next; Some(Ok(PublicKey::from_raw(next))) }
                1 => None,
                rc => Some(Err(self.agent.sess.rc(rc).err().unwrap())),
            }
        }
    }
}

impl<'a> PublicKey<'a> {
    pub unsafe fn from_raw<'a>(raw: *mut raw::libssh2_agent_publickey)
                               -> PublicKey<'a> {
        PublicKey {
            raw: raw,
            marker1: marker::NoSync,
            marker2: marker::NoSend,
            marker3: marker::ContravariantLifetime,
            marker4: marker::NoCopy,
        }
    }

    /// Return the data of this public key.
    pub fn blob(&self) -> &[u8] {
        unsafe {
            mem::transmute(stdraw::Slice {
                data: (*self.raw).blob as *const u8,
                len: (*self.raw).blob_len as uint,
            })
        }
    }

    /// Returns the comment in a printable format
    pub fn comment(&self) -> &str {
        unsafe {
            str::from_utf8(::opt_bytes(self, (*self.raw).comment).unwrap())
                .unwrap()
        }
    }

    /// Gain access to the underlying raw pointer
    pub fn raw(&self) -> *mut raw::libssh2_agent_publickey { self.raw }
}
