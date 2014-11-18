use std::kinds::marker;
use std::str;
use libc::{c_int, size_t};

use {raw, Session, Error, KnownHostFileKind, CheckResult};

/// A set of known hosts which can be used to verify the identity of a remote
/// server.
///
/// # Example
///
/// ```no_run
/// use std::os;
/// use ssh2::{mod, CheckResult, HostKeyType, KnownHostKeyFormat};
///
/// fn check_known_host(session: &ssh2::Session, host: &str) {
///     let mut known_hosts = session.known_hosts().unwrap();
///
///     // Initialize the known hosts with a global known hosts file
///     let file = Path::new(os::getenv("HOME").unwrap()).join(".ssh/known_hosts");
///     known_hosts.read_file(&file, ssh2::OpenSSH).unwrap();
///
///     // Now check to see if the seesion's host key is anywhere in the known
///     // hosts file
///     let (key, key_type) = session.host_key().unwrap();
///     match known_hosts.check(host, key) {
///         CheckResult::Match => return, // all good!
///         CheckResult::NotFound => {}   // ok, we'll add it
///         CheckResult::Mismatch => {
///             panic!("host mismatch, man in the middle attack?!")
///         }
///         CheckResult::Failure => panic!("failed to check the known hosts"),
///     }
///
///     println!("adding {} to the known hosts", host);
///
///     known_hosts.add(host, key, host, match key_type {
///         HostKeyType::Rsa => KnownHostKeyFormat::SshRsa,
///         HostKeyType::Dss => KnownHostKeyFormat::SshDss,
///         HostKeyType::Unknown => panic!("unknown type of key!"),
///     }).unwrap();
///     known_hosts.write_file(&file, ssh2::OpenSSH).unwrap();
/// }
/// ```
pub struct KnownHosts<'a> {
    raw: *mut raw::LIBSSH2_KNOWNHOSTS,
    sess: &'a Session,
    marker: marker::NoSync,
}

/// Iterator over the hosts in a `KnownHosts` structure.
pub struct Hosts<'a> {
    prev: *mut raw::libssh2_knownhost,
    hosts: &'a KnownHosts<'a>,
}

/// Structure representing a known host as part of a `KnownHosts` structure.
pub struct Host<'a> {
    raw: *mut raw::libssh2_knownhost,
    marker1: marker::NoSync,
    marker2: marker::NoSend,
    marker3: marker::ContravariantLifetime<'a>,
    marker4: marker::NoCopy,
}

impl<'a> KnownHosts<'a> {
    /// Wraps a raw pointer in a new KnownHosts structure tied to the lifetime
    /// of the given session.
    ///
    /// This consumes ownership of `raw`.
    pub unsafe fn from_raw(sess: &Session,
                           raw: *mut raw::LIBSSH2_KNOWNHOSTS) -> KnownHosts {
        KnownHosts {
            raw: raw,
            sess: sess,
            marker: marker::NoSync,
        }
    }

    /// Reads a collection of known hosts from a specified file and adds them to
    /// the collection of known hosts.
    pub fn read_file(&mut self, file: &Path, kind: KnownHostFileKind)
                     -> Result<uint, Error> {
        let file = file.to_c_str();
        let n = unsafe {
            raw::libssh2_knownhost_readfile(self.raw, file.as_ptr(),
                                            kind as c_int)
        };
        if n < 0 { try!(self.sess.rc(n)) }
        Ok(n as uint)
    }

    /// Read a line as if it were from a known hosts file.
    pub fn read_str(&mut self, s: &str, kind: KnownHostFileKind)
                     -> Result<(), Error> {
        self.sess.rc(unsafe {
            raw::libssh2_knownhost_readline(self.raw,
                                            s.as_ptr() as *const _,
                                            s.len() as size_t,
                                            kind as c_int)
        })
    }

    /// Writes all the known hosts to the specified file using the specified
    /// file format.
    pub fn write_file(&self, file: &Path, kind: KnownHostFileKind)
                      -> Result<(), Error> {
        let file = file.to_c_str();
        let n = unsafe {
            raw::libssh2_knownhost_writefile(self.raw, file.as_ptr(),
                                             kind as c_int)
        };
        self.sess.rc(n)
    }

    /// Converts a single known host to a single line of output for storage,
    /// using the 'type' output format.
    pub fn write_string(&self, host: &Host, kind: KnownHostFileKind)
                        -> Result<String, Error> {
        let mut v = Vec::with_capacity(128);
        loop {
            let mut outlen = 0;
            unsafe {
                let rc = raw::libssh2_knownhost_writeline(self.raw,
                                                          host.raw,
                                                          v.as_mut_ptr()
                                                              as *mut _,
                                                          v.capacity() as size_t,
                                                          &mut outlen,
                                                          kind as c_int);
                if rc == raw::LIBSSH2_ERROR_BUFFER_TOO_SMALL {
                    v.reserve(outlen as uint);
                } else {
                    try!(self.sess.rc(rc));
                    v.set_len(outlen as uint);
                    break
                }
            }
        }
        Ok(String::from_utf8(v).unwrap())
    }

    /// Create an iterator over all of the known hosts in this structure.
    pub fn iter(&self) -> Hosts {
        Hosts { prev: 0 as *mut _, hosts: self }
    }

    /// Delete a known host entry from the collection of known hosts.
    pub fn remove(&self, host: Host) -> Result<(), Error> {
        self.sess.rc(unsafe {
            raw::libssh2_knownhost_del(self.raw, host.raw)
        })
    }

    /// Checks a host and its associated key against the collection of known
    /// hosts, and returns info back about the (partially) matched entry.
    ///
    /// The host name can be the IP numerical address of the host or the full
    /// name. The key must be the raw data of the key.
    pub fn check(&self, host: &str, key: &[u8]) -> CheckResult {
        self.check_port_(host, -1, key)
    }

    /// Same as `check`, but takes a port as well.
    pub fn check_port(&self, host: &str, port: u16, key: &[u8]) -> CheckResult {
        self.check_port_(host, port as int, key)
    }

    fn check_port_(&self, host: &str, port: int, key: &[u8]) -> CheckResult {
        let host = host.to_c_str();
        let flags = raw::LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                    raw::LIBSSH2_KNOWNHOST_KEYENC_RAW;
        unsafe {
            let rc = raw::libssh2_knownhost_checkp(self.raw,
                                                   host.as_ptr(),
                                                   port as c_int,
                                                   key.as_ptr() as *const _,
                                                   key.len() as size_t,
                                                   flags,
                                                   0 as *mut _);
            match rc {
                raw::LIBSSH2_KNOWNHOST_CHECK_MATCH => CheckResult::Match,
                raw::LIBSSH2_KNOWNHOST_CHECK_MISMATCH => CheckResult::Mismatch,
                raw::LIBSSH2_KNOWNHOST_CHECK_NOTFOUND => CheckResult::NotFound,
                _ => CheckResult::Failure,
            }
        }
    }

    /// Adds a known host to the collection of known hosts.
    ///
    /// The host is the host name in plain text. The host name can be the IP
    /// numerical address of the host or the full name. If you want to add a key
    /// for a specific port number for the given host, you must provide the host
    /// name like '[host]:port' with the actual characters '[' and ']' enclosing
    /// the host name and a colon separating the host part from the port number.
    /// For example: "[host.example.com]:222".
    ///
    /// The key provided must be the raw key for the host.
    pub fn add(&mut self, host: &str, key: &[u8], comment: &str,
               fmt: ::KnownHostKeyFormat)
               -> Result<(), Error> {
        let host = host.to_c_str();
        let flags = raw::LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                    raw::LIBSSH2_KNOWNHOST_KEYENC_RAW |
                    (fmt as c_int);
        unsafe {
            let rc = raw::libssh2_knownhost_addc(self.raw,
                                                 host.as_ptr() as *mut _,
                                                 0 as *mut _,
                                                 key.as_ptr() as *mut _,
                                                 key.len() as size_t,
                                                 comment.as_ptr() as *const _,
                                                 comment.len() as size_t,
                                                 flags,
                                                 0 as *mut _);
            self.sess.rc(rc)
        }
    }
}

#[unsafe_destructor]
impl<'a> Drop for KnownHosts<'a> {
    fn drop(&mut self) {
        unsafe { raw::libssh2_knownhost_free(self.raw) }
    }
}

impl<'a> Iterator<Result<Host<'a>, Error>> for Hosts<'a> {
    fn next(&mut self) -> Option<Result<Host<'a>, Error>> {
        unsafe {
            let mut next = 0 as *mut _;
            match raw::libssh2_knownhost_get(self.hosts.raw,
                                             &mut next,
                                             self.prev) {
                0 => { self.prev = next; Some(Ok(Host::from_raw(next))) }
                1 => None,
                rc => Some(Err(self.hosts.sess.rc(rc).err().unwrap())),
            }
        }
    }
}

impl<'a> Host<'a> {
    /// Creates a new host from its raw counterpart.
    ///
    /// Unsafe as there are no restrictions on the lifetime of the host returned
    /// and the validity of `raw` is not known.
    pub unsafe fn from_raw<'a>(raw: *mut raw::libssh2_knownhost)
                               -> Host<'a> {
        Host {
            raw: raw,
            marker1: marker::NoSync,
            marker2: marker::NoSend,
            marker3: marker::ContravariantLifetime,
            marker4: marker::NoCopy,
        }
    }

    /// This is `None` if no plain text host name exists.
    pub fn name(&self) -> Option<&str> {
        unsafe {
            ::opt_bytes(self, (*self.raw).name as *const _)
                       .and_then(str::from_utf8)
        }
    }

    /// Returns the key in base64/printable format
    pub fn key(&self) -> &str {
        let bytes = unsafe {
            ::opt_bytes(self, (*self.raw).key as *const _).unwrap()
        };
        str::from_utf8(bytes).unwrap()
    }

    /// Gain access to the underlying raw pointer
    pub fn raw(&self) -> *mut raw::libssh2_knownhost { self.raw }
}
