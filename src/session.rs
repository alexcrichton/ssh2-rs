use std::kinds::marker;
use std::mem;
use std::raw as stdraw;
use std::str;
use libc;

use {raw, Error, DisconnectCode, ByApplication, SessionFlag, HostKeyType};
use {MethodType, Agent};

pub struct Session {
    raw: *mut raw::LIBSSH2_SESSION,
    marker: marker::NoSync,
}

impl Session {
    /// Initializes an SSH session object
    pub fn new() -> Option<Session> {
        ::init();
        unsafe {
            let ret = raw::libssh2_session_init_ex(None, None, None);
            if ret.is_null() { return None  }
            Some(Session::from_raw(ret))
        }
    }

    /// Takes ownership of the given raw pointer and wraps it in a session.
    ///
    /// This is unsafe as there is no guarantee about the validity of `raw`.
    pub unsafe fn from_raw(raw: *mut raw::LIBSSH2_SESSION) -> Session {
        Session {
            raw: raw,
            marker: marker::NoSync,
        }
    }

    /// Get the remote banner
    ///
    /// Once the session has been setup and handshake() has completed
    /// successfully, this function can be used to get the server id from the
    /// banner each server presents.
    ///
    /// May return `None` on invalid utf-8 or if an error has ocurred.
    pub fn banner(&self) -> Option<&str> {
        self.banner_bytes().and_then(str::from_utf8)
    }

    /// See `banner`.
    ///
    /// Will only return `None` if an error has ocurred.
    pub fn banner_bytes(&self) -> Option<&[u8]> {
        unsafe { ::opt_bytes(self, raw::libssh2_session_banner_get(self.raw)) }
    }

    /// Set the SSH protocol banner for the local client
    ///
    /// Set the banner that will be sent to the remote host when the SSH session
    /// is started with handshake(). This is optional; a banner
    /// corresponding to the protocol and libssh2 version will be sent by
    /// default.
    pub fn set_banner(&self, banner: &str) -> Result<(), Error> {
        let banner = banner.to_c_str();
        unsafe {
            self.rc(raw::libssh2_session_banner_set(self.raw, banner.as_ptr()))
        }
    }

    /// Terminate the transport layer.
    ///
    /// Send a disconnect message to the remote host associated with session,
    /// along with a reason symbol and a verbose description.
    pub fn disconnect(&self,
                      reason: Option<DisconnectCode>,
                      description: &str,
                      lang: Option<&str>) -> Result<(), Error> {
        let reason = reason.unwrap_or(ByApplication) as libc::c_int;
        let description = description.to_c_str();
        let lang = lang.unwrap_or("").to_c_str();
        unsafe {
            self.rc(raw::libssh2_session_disconnect_ex(self.raw,
                                                       reason,
                                                       description.as_ptr(),
                                                       lang.as_ptr()))
        }
    }

    /// Enable or disable a flag for this session.
    pub fn flag(&self, flag: SessionFlag, enable: bool) -> Result<(), Error> {
        unsafe {
            self.rc(raw::libssh2_session_flag(self.raw, flag as libc::c_int,
                                              enable as libc::c_int))
        }
    }

    /// Returns whether the session was previously set to nonblocking.
    pub fn is_blocking(&self) -> bool {
        unsafe { raw::libssh2_session_get_blocking(self.raw) != 0 }
    }

    /// Set or clear blocking mode on session
    ///
    /// Set or clear blocking mode on the selected on the session. This will
    /// instantly affect any channels associated with this session. If a read
    /// is performed on a session with no data currently available, a blocking
    /// session will wait for data to arrive and return what it receives. A
    /// non-blocking session will return immediately with an empty buffer. If a
    /// write is performed on a session with no room for more data, a blocking
    /// session will wait for room. A non-blocking session will return
    /// immediately without writing anything.
    pub fn set_blocking(&self, blocking: bool) {
        unsafe {
            raw::libssh2_session_set_blocking(self.raw, blocking as libc::c_int)
        }
    }

    /// Returns the timeout, in milliseconds, for how long blocking calls may
    /// wait until they time out.
    ///
    /// A timeout of 0 signifies no timeout.
    pub fn timeout(&self) -> uint {
        unsafe { raw::libssh2_session_get_timeout(self.raw) as uint }
    }

    /// Set timeout for blocking functions.
    ///
    /// Set the timeout in milliseconds for how long a blocking the libssh2
    /// function calls may wait until they consider the situation an error and
    /// return an error.
    ///
    /// By default or if you set the timeout to zero, libssh2 has no timeout
    /// for blocking functions.
    pub fn set_timeout(&self, timeout_ms: uint) {
        let timeout_ms = timeout_ms as libc::c_long;
        unsafe { raw::libssh2_session_set_timeout(self.raw, timeout_ms) }
    }

    /// Get the remote key.
    ///
    /// Returns `None` if something went wrong.
    pub fn hostkey(&self) -> Option<(&[u8], HostKeyType)> {
        let mut len = 0;
        let mut kind = 0;
        unsafe {
            let ret = raw::libssh2_session_hostkey(self.raw, &mut len, &mut kind);
            if ret.is_null() { return None }
            let data: &[u8] = mem::transmute(stdraw::Slice {
                data: ret as *const u8,
                len: len as uint,
            });
            let kind = match kind {
                raw::LIBSSH2_HOSTKEY_TYPE_RSA => ::TypeRsa,
                raw::LIBSSH2_HOSTKEY_TYPE_DSS => ::TypeDss,
                _ => ::TypeUnknown,
            };
            Some((data, kind))
        }
    }

    /// Set preferred key exchange method
    ///
    /// The preferences provided are a comma delimited list of preferred methods
    /// to use with the most preferred listed first and the least preferred
    /// listed last. If a method is listed which is not supported by libssh2 it
    /// will be ignored and not sent to the remote host during protocol
    /// negotiation.
    pub fn method_pref(&self,
                       method_type: MethodType,
                       prefs: &str) -> Result<(), Error> {
        let prefs = prefs.to_c_str();
        unsafe {
            self.rc(raw::libssh2_session_method_pref(self.raw,
                                                     method_type as libc::c_int,
                                                     prefs.as_ptr()))
        }
    }

    /// Return the currently active algorithms.
    ///
    /// Returns the actual method negotiated for a particular transport
    /// parameter. May return `None` if the session has not yet been started.
    pub fn methods(&self, method_type: MethodType) -> Option<&str> {
        unsafe {
            let ptr = raw::libssh2_session_methods(self.raw,
                                                   method_type as libc::c_int);
            ::opt_bytes(self, ptr).and_then(str::from_utf8)
        }
    }

    /// Get list of supported algorithms.
    pub fn supported_algs(&self, method_type: MethodType)
                          -> Result<Vec<&'static str>, Error> {
        let method_type = method_type as libc::c_int;
        let mut ret = Vec::new();
        unsafe {
            let mut ptr = 0 as *mut _;
            let rc = raw::libssh2_session_supported_algs(self.raw, method_type,
                                                         &mut ptr);
            if rc <= 0 { try!(self.rc(rc)) }
            for i in range(0, rc as int) {
                ret.push(str::raw::c_str_to_static_slice(*ptr.offset(i)));
            }
            raw::libssh2_free(self.raw, ptr as *mut libc::c_void);
        }
        Ok(ret)
    }

    /// Init an ssh-agent handle.
    ///
    /// The returned agent will still need to be connected manually before use.
    pub fn agent(&self) -> Option<Agent> {
        unsafe {
            let ptr = raw::libssh2_agent_init(self.raw);
            if ptr.is_null() {
                None
            } else {
                Some(Agent::from_raw(self, ptr))
            }
        }
    }

    /// Gain access to the underlying raw libssh2 session pointer.
    pub fn raw(&self) -> *mut raw::LIBSSH2_SESSION { self.raw }

    /// Translate a return code into a Rust-`Result`.
    pub fn rc(&self, rc: libc::c_int) -> Result<(), Error> {
        if rc == 0 {
            Ok(())
        } else {
            match Error::last_error(self) {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            assert_eq!(raw::libssh2_session_free(self.raw), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use Session;

    #[test]
    fn smoke() {
        let sess = Session::new().unwrap();
        assert!(sess.banner_bytes().is_none());
        sess.set_banner("foo").unwrap();
        assert!(sess.is_blocking());
        assert_eq!(sess.timeout(), 0);
        sess.flag(::Compress, true).unwrap();
        assert!(sess.hostkey().is_none());
        sess.method_pref(::MethodKex, "diffie-hellman-group14-sha1").unwrap();
        assert!(sess.methods(::MethodKex).is_none());
        sess.set_blocking(true);
        sess.set_timeout(0);
        sess.supported_algs(::MethodKex).unwrap();
        sess.supported_algs(::MethodHostKey).unwrap();
    }
}
