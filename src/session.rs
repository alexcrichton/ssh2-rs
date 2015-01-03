use std::c_str::ToCStr;
use std::io;
use std::kinds::marker;
use std::mem;
use std::slice;
use std::str;
use libc::{self, c_uint, c_int, c_void, c_long};

use {raw, Error, DisconnectCode, ByApplication, SessionFlag, HostKeyType};
use {MethodType, Agent, Channel, Listener, HashType, KnownHosts, Sftp};

/// An SSH session, typically representing one TCP connection.
///
/// All other structures are based on an SSH session and cannot outlive a
/// session. Sessions are created and then have the TCP socket handed to them
/// (via the `handshake` method).
pub struct Session {
    raw: *mut raw::LIBSSH2_SESSION,
    marker: marker::NoSync,
}

impl Session {
    /// Initializes an SSH session object.
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
        self.banner_bytes().and_then(|s| str::from_utf8(s).ok())
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
        let reason = reason.unwrap_or(ByApplication) as c_int;
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
            self.rc(raw::libssh2_session_flag(self.raw, flag as c_int,
                                              enable as c_int))
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
            raw::libssh2_session_set_blocking(self.raw, blocking as c_int)
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
        let timeout_ms = timeout_ms as c_long;
        unsafe { raw::libssh2_session_set_timeout(self.raw, timeout_ms) }
    }

    /// Get the remote key.
    ///
    /// Returns `None` if something went wrong.
    pub fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        let mut len = 0;
        let mut kind = 0;
        unsafe {
            let ret = raw::libssh2_session_hostkey(self.raw, &mut len, &mut kind);
            if ret.is_null() { return None }
            let ret = ret as *const u8;
            let data = mem::transmute(slice::from_raw_buf(&ret, len as uint));
            let kind = match kind {
                raw::LIBSSH2_HOSTKEY_TYPE_RSA => HostKeyType::Rsa,
                raw::LIBSSH2_HOSTKEY_TYPE_DSS => HostKeyType::Dss,
                _ => HostKeyType::Unknown,
            };
            Some((data, kind))
        }
    }

    /// Returns the computed digest of the remote system's hostkey.
    ///
    /// The bytes returned are the raw hash, and are not printable. If the hash
    /// is not yet available `None` is returned.
    pub fn host_key_hash(&self, hash: HashType) -> Option<&[u8]> {
        let len = match hash {
            HashType::Md5 => 16,
            HashType::Sha1 => 20,
        };
        unsafe {
            let ret = raw::libssh2_hostkey_hash(self.raw, hash as c_int);
            if ret.is_null() {
                None
            } else {
                let ret = ret as *const u8;
                Some(mem::transmute(slice::from_raw_buf(&ret, len)))
            }
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
                                                     method_type as c_int,
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
                                                   method_type as c_int);
            ::opt_bytes(self, ptr).and_then(|s| str::from_utf8(s).ok())
        }
    }

    /// Get list of supported algorithms.
    pub fn supported_algs(&self, method_type: MethodType)
                          -> Result<Vec<&'static str>, Error> {
        let method_type = method_type as c_int;
        let mut ret = Vec::new();
        unsafe {
            let mut ptr = 0 as *mut _;
            let rc = raw::libssh2_session_supported_algs(self.raw, method_type,
                                                         &mut ptr);
            if rc <= 0 { try!(self.rc(rc)) }
            for i in range(0, rc as int) {
                ret.push(str::from_c_str(*ptr.offset(i)));
            }
            raw::libssh2_free(self.raw, ptr as *mut c_void);
        }
        Ok(ret)
    }

    /// Init an ssh-agent handle.
    ///
    /// The returned agent will still need to be connected manually before use.
    pub fn agent(&self) -> Result<Agent, Error> {
        unsafe {
            let ptr = raw::libssh2_agent_init(self.raw);
            if ptr.is_null() {
                Err(Error::last_error(self).unwrap())
            } else {
                Ok(Agent::from_raw(self, ptr))
            }
        }
    }

    /// Begin transport layer protocol negotiation with the connected host.
    ///
    /// The socket provided is a connected socket descriptor. Typically a TCP
    /// connection though the protocol allows for any reliable transport and
    /// the library will attempt to use any berkeley socket.
    pub fn handshake(&mut self, socket: raw::libssh2_socket_t)
                     -> Result<(), Error> {
        unsafe {
            self.rc(raw::libssh2_session_handshake(self.raw, socket))
        }
    }

    /// Allocate a new channel for exchanging data with the server.
    ///
    /// This is typically not called directly but rather through
    /// `channel_open_session`, `channel_direct_tcpip`, or
    /// `channel_forward_listen`.
    pub fn channel_open(&self, channel_type: &str,
                        window_size: uint, packet_size: uint,
                        message: Option<&str>) -> Result<Channel, Error> {
        let ret = unsafe {
            let message_len = message.map(|s| s.len()).unwrap_or(0);
            raw::libssh2_channel_open_ex(self.raw,
                                         channel_type.as_ptr() as *const _,
                                         channel_type.len() as c_uint,
                                         window_size as c_uint,
                                         packet_size as c_uint,
                                         message.as_ref().map(|s| s.as_ptr())
                                                .unwrap_or(0 as *const _)
                                                as *const _,
                                         message_len as c_uint)
        };
        if ret.is_null() {
            Err(Error::last_error(self).unwrap())
        } else {
            Ok(unsafe { Channel::from_raw(self, ret) })
        }
    }

    /// Establish a new session-based channel.
    pub fn channel_session(&self) -> Result<Channel, Error> {
        self.channel_open("session",
                          raw::LIBSSH2_CHANNEL_WINDOW_DEFAULT as uint,
                          raw::LIBSSH2_CHANNEL_PACKET_DEFAULT as uint, None)
    }

    /// Tunnel a TCP connection through an SSH session.
    ///
    /// Tunnel a TCP/IP connection through the SSH transport via the remote host
    /// to a third party. Communication from the client to the SSH server
    /// remains encrypted, communication from the server to the 3rd party host
    /// travels in cleartext.
    ///
    /// The optional `src` argument is the host/port to tell the SSH server
    /// where the connection originated from.
    pub fn channel_direct_tcpip(&self, host: &str, port: u16,
                                src: Option<(&str, u16)>)
                                -> Result<Channel, Error> {
        let (shost, sport) = src.unwrap_or(("127.0.0.1", 22));
        let host = host.to_c_str();
        let shost = shost.to_c_str();
        let ret = unsafe {
            raw::libssh2_channel_direct_tcpip_ex(self.raw,
                                                 host.as_ptr(),
                                                 port as c_int,
                                                 shost.as_ptr(),
                                                 sport as c_int)
        };
        if ret.is_null() {
            Err(Error::last_error(self).unwrap())
        } else {
            Ok(unsafe { Channel::from_raw(self, ret) })
        }
    }

    /// Instruct the remote SSH server to begin listening for inbound TCP/IP
    /// connections.
    ///
    /// New connections will be queued by the library until accepted by
    /// `forward_accept`.
    pub fn channel_forward_listen(&self,
                                  remote_port: u16,
                                  host: Option<&str>,
                                  queue_maxsize: Option<uint>)
                                  -> Result<(Listener, u16), Error> {
        let mut bound_port = 0;
        let ret = unsafe {
            raw::libssh2_channel_forward_listen_ex(self.raw,
                                                   host.map(|s| s.as_ptr())
                                                       .unwrap_or(0 as *const _)
                                                           as *mut _,
                                                   remote_port as c_int,
                                                   &mut bound_port,
                                                   queue_maxsize.unwrap_or(0)
                                                        as c_int)
        };
        if ret.is_null() {
            Err(Error::last_error(self).unwrap())
        } else {
            Ok((unsafe { Listener::from_raw(self, ret) }, bound_port as u16))
        }
    }

    /// Attempt basic password authentication.
    ///
    /// Note that many SSH servers which appear to support ordinary password
    /// authentication actually have it disabled and use Keyboard Interactive
    /// authentication (routed via PAM or another authentication backed)
    /// instead.
    pub fn userauth_password(&self, username: &str, password: &str)
                             -> Result<(), Error> {
        self.rc(unsafe {
            raw::libssh2_userauth_password_ex(self.raw,
                                              username.as_ptr() as *const _,
                                              username.len() as c_uint,
                                              password.as_ptr() as *const _,
                                              password.len() as c_uint,
                                              None)
        })
    }

    /// Attempt public key authentication using a PEM encoded private key file
    /// stored on disk.
    pub fn userauth_pubkey_file(&self, username: &str,
                                pubkey: Option<&Path>,
                                privatekey: &Path,
                                passphrase: Option<&str>) -> Result<(), Error> {
        let pubkey = pubkey.map(|s| s.to_c_str());
        let privatekey = privatekey.to_c_str();
        let passphrase = passphrase.map(|s| s.to_c_str());
        self.rc(unsafe {
            raw::libssh2_userauth_publickey_fromfile_ex(self.raw,
                    username.as_ptr() as *const _,
                    username.len() as c_uint,
                    pubkey.as_ref().map(|s| s.as_ptr()).unwrap_or(0 as *const _),
                    privatekey.as_ptr(),
                    passphrase.as_ref().map(|s| s.as_ptr())
                              .unwrap_or(0 as *const _))
        })
    }

    /// Umm... I wish this were documented in libssh2?
    pub fn userauth_hostbased_file(&self, username: &str,
                                   publickey: &Path,
                                   privatekey: &Path,
                                   passphrase: Option<&str>,
                                   hostname: &str,
                                   local_username: Option<&str>)
                                   -> Result<(), Error> {
        let publickey = publickey.to_c_str();
        let privatekey = privatekey.to_c_str();
        let passphrase = passphrase.map(|s| s.to_c_str());
        let local_username = match local_username {
            Some(local) => local,
            None => username,
        };
        self.rc(unsafe {
            raw::libssh2_userauth_hostbased_fromfile_ex(self.raw,
                    username.as_ptr() as *const _,
                    username.len() as c_uint,
                    publickey.as_ptr(),
                    privatekey.as_ptr(),
                    passphrase.as_ref().map(|s| s.as_ptr())
                              .unwrap_or(0 as *const _),
                    hostname.as_ptr() as *const _,
                    hostname.len() as c_uint,
                    local_username.as_ptr() as *const _,
                    local_username.len() as c_uint)
        })
    }

    /// Indicates whether or not the named session has been successfully
    /// authenticated.
    pub fn authenticated(&self) -> bool {
        unsafe { raw::libssh2_userauth_authenticated(self.raw) != 0 }
    }

    /// Send a SSH_USERAUTH_NONE request to the remote host.
    ///
    /// Unless the remote host is configured to accept none as a viable
    /// authentication scheme (unlikely), it will return SSH_USERAUTH_FAILURE
    /// along with a listing of what authentication schemes it does support. In
    /// the unlikely event that none authentication succeeds, this method with
    /// return NULL. This case may be distinguished from a failing case by
    /// examining libssh2_userauth_authenticated.
    ///
    /// The return value is a comma-separated string of supported auth schemes.
    pub fn auth_methods(&self, username: &str) -> Result<&str, Error> {
        let len = username.len();
        let username = username.to_c_str();
        unsafe {
            let ret = raw::libssh2_userauth_list(self.raw, username.as_ptr(),
                                                 len as c_uint);
            if ret.is_null() {
                Err(Error::last_error(self).unwrap())
            } else {
                Ok(str::from_c_str(ret))
            }
        }
    }

    /// Set how often keepalive messages should be sent.
    ///
    /// The want_reply argument indicates whether the keepalive messages should
    /// request a response from the server.
    ///
    /// The interval argument is number of seconds that can pass without any
    /// I/O, use 0 (the default) to disable keepalives. To avoid some busy-loop
    /// corner-cases, if you specify an interval of 1 it will be treated as 2.
    pub fn keepalive_set(&self, want_reply: bool, interval: uint)
                         -> Result<(), Error> {
        unsafe {
            self.rc(raw::libssh2_keepalive_config(self.raw, want_reply as c_int,
                                                  interval as c_uint))
        }
    }

    /// Send a keepalive message if needed.
    ///
    /// Returns how many seconds you can sleep after this call before you need
    /// to call it again.
    pub fn keepalive_send(&self) -> Result<uint, Error> {
        let mut ret = 0;
        let rc = unsafe { raw::libssh2_keepalive_send(self.raw, &mut ret) };
        try!(self.rc(rc));
        Ok(ret as uint)
    }

    /// Init a collection of known hosts for this session.
    ///
    /// Returns the handle to an internal representation of a known host
    /// collection.
    pub fn known_hosts(&self) -> Result<KnownHosts, Error> {
        unsafe {
            let ret = raw::libssh2_knownhost_init(self.raw);
            if ret.is_null() {
                Err(Error::last_error(self).unwrap())
            } else {
                Ok(KnownHosts::from_raw(self, ret))
            }
        }
    }

    /// Request a file from the remote host via SCP.
    pub fn scp_recv(&self, path: &Path)
                    -> Result<(Channel, io::FileStat), Error> {
        let path = path.to_c_str();
        unsafe {
            let mut sb: libc::stat = mem::zeroed();
            let ret = raw::libssh2_scp_recv(self.raw, path.as_ptr(), &mut sb);
            if ret.is_null() { return Err(Error::last_error(self).unwrap()) }

            // Hm, apparently when we scp_recv() a file the actual channel
            // itself does not respond well to read_to_end(), and it also sends
            // an extra 0 byte (or so it seems). To work around this we
            // artificially limit the channel to a certain amount of bytes that
            // can be read.
            let mut c = Channel::from_raw(self, ret);
            c.limit_read(sb.st_size as u64);
            Ok((c, mkstat(&sb)))
        }
    }

    /// Send a file to the remote host via SCP.
    ///
    /// The `remote_path` provided will the remote file name. The `times`
    /// argument is a tuple of (mtime, atime), and will default to the remote
    /// host's current time if not specified.
    pub fn scp_send(&self, remote_path: &Path, mode: io::FilePermission,
                    size: u64, times: Option<(u64, u64)>)
                    -> Result<Channel, Error> {
        let path = remote_path.to_c_str();
        let (mtime, atime) = times.unwrap_or((0, 0));
        unsafe {
            let ret = raw::libssh2_scp_send64(self.raw,
                                              path.as_ptr(),
                                              mode.bits() as c_int,
                                              size,
                                              mtime as libc::time_t,
                                              atime as libc::time_t);

            if ret.is_null() {
                Err(Error::last_error(self).unwrap())
            } else {
                Ok(Channel::from_raw(self, ret))
            }
        }
    }

    /// Open a channel and initialize the SFTP subsystem.
    ///
    /// Although the SFTP subsystem operates over the same type of channel as
    /// those exported by the Channel API, the protocol itself implements its
    /// own unique binary packet protocol which must be managed with the
    /// methods on `Sftp`.
    pub fn sftp(&self) -> Result<Sftp, Error> {
        unsafe {
            let ret = raw::libssh2_sftp_init(self.raw);
            if ret.is_null() {
                Err(Error::last_error(self).unwrap())
            } else {
                Ok(Sftp::from_raw(self, ret))
            }
        }
    }

    /// Gain access to the underlying raw libssh2 session pointer.
    pub fn raw(&self) -> *mut raw::LIBSSH2_SESSION { self.raw }

    /// Translate a return code into a Rust-`Result`.
    pub fn rc(&self, rc: c_int) -> Result<(), Error> {
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

// Sure do wish this was exported in libnative!
fn mkstat(stat: &libc::stat) -> io::FileStat {
    #[cfg(windows)] type Mode = libc::c_int;
    #[cfg(unix)]    type Mode = libc::mode_t;

    // FileStat times are in milliseconds
    fn mktime(secs: u64, nsecs: u64) -> u64 { secs * 1000 + nsecs / 1000000 }

    #[cfg(all(not(target_os = "linux"), not(target_os = "android")))]
    fn flags(stat: &libc::stat) -> u64 { stat.st_flags as u64 }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn flags(_stat: &libc::stat) -> u64 { 0 }

    #[cfg(all(not(target_os = "linux"), not(target_os = "android")))]
    fn gen(stat: &libc::stat) -> u64 { stat.st_gen as u64 }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn gen(_stat: &libc::stat) -> u64 { 0 }

    io::FileStat {
        size: stat.st_size as u64,
        kind: match (stat.st_mode as Mode) & libc::S_IFMT {
            libc::S_IFREG => io::FileType::RegularFile,
            libc::S_IFDIR => io::FileType::Directory,
            libc::S_IFIFO => io::FileType::NamedPipe,
            libc::S_IFBLK => io::FileType::BlockSpecial,
            libc::S_IFLNK => io::FileType::Symlink,
            _ => io::FileType::Unknown,
        },
        perm: io::FilePermission::from_bits_truncate(stat.st_mode as u32),
        created: mktime(stat.st_ctime as u64, stat.st_ctime_nsec as u64),
        modified: mktime(stat.st_mtime as u64, stat.st_mtime_nsec as u64),
        accessed: mktime(stat.st_atime as u64, stat.st_atime_nsec as u64),
        unstable: io::UnstableFileStat {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            rdev: stat.st_rdev as u64,
            nlink: stat.st_nlink as u64,
            uid: stat.st_uid as u64,
            gid: stat.st_gid as u64,
            blksize: stat.st_blksize as u64,
            blocks: stat.st_blocks as u64,
            flags: flags(stat),
            gen: gen(stat),
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
