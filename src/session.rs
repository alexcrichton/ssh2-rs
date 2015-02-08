use std::ffi::CString;
use std::old_io::{self, TcpStream};
use std::mem;
use std::slice;
use std::str;
use libc::{self, c_uint, c_int, c_void, c_long};

use {raw, Error, DisconnectCode, ByApplication, HostKeyType};
use {MethodType, Agent, Channel, Listener, HashType, KnownHosts, Sftp};
use util::{Binding, SessionBinding};

/// An SSH session, typically representing one TCP connection.
///
/// All other structures are based on an SSH session and cannot outlive a
/// session. Sessions are created and then have the TCP socket handed to them
/// (via the `handshake` method).
pub struct Session {
    raw: *mut raw::LIBSSH2_SESSION,
}

unsafe impl Send for Session {}

impl Session {
    /// Initializes an SSH session object.
    ///
    /// This function does not associate the session with a remote connection
    /// just yet. Various configuration options can be set such as the blocking
    /// mode, compression, sigpipe, the banner, etc. To associate this session
    /// with a TCP connection, use the `handshake` method to pass in an
    /// already-established TCP socket.
    pub fn new() -> Option<Session> {
        ::init();
        unsafe {
            let ret = raw::libssh2_session_init_ex(None, None, None);
            if ret.is_null() {None} else {Some(Binding::from_raw(ret))}
        }
    }

    /// Set the SSH protocol banner for the local client
    ///
    /// Set the banner that will be sent to the remote host when the SSH session
    /// is started with handshake(). This is optional; a banner
    /// corresponding to the protocol and libssh2 version will be sent by
    /// default.
    pub fn set_banner(&self, banner: &str) -> Result<(), Error> {
        let banner = CString::from_slice(banner.as_bytes());
        unsafe {
            self.rc(raw::libssh2_session_banner_set(self.raw, banner.as_ptr()))
        }
    }

    /// Flag indicating whether SIGPIPE signals will be allowed or blocked.
    ///
    /// By default (on relevant platforms) this library will attempt to block
    /// and catch SIGPIPE signals. Setting this flag to `true` will cause
    /// the library to not attempt to block SIGPIPE from the underlying socket
    /// layer.
    pub fn set_allow_sigpipe(&self, block: bool) {
        let res = unsafe {
            self.rc(raw::libssh2_session_flag(self.raw,
                                              raw::LIBSSH2_FLAG_SIGPIPE as c_int,
                                              block as c_int))
        };
        res.unwrap();
    }

    /// Flag indicating whether this library will attempt to negotiate
    /// compression.
    ///
    /// If set - before the connection negotiation is performed - libssh2 will
    /// try to negotiate compression enabling for this connection. By default
    /// libssh2 will not attempt to use compression.
    pub fn set_compress(&self, compress: bool) {
        let res = unsafe {
            self.rc(raw::libssh2_session_flag(self.raw,
                                              raw::LIBSSH2_FLAG_COMPRESS as c_int,
                                              compress as c_int))
        };
        res.unwrap();
    }

    /// Set or clear blocking mode on session
    ///
    /// This will instantly affect any channels associated with this session. If
    /// a read is performed on a session with no data currently available, a
    /// blocking session will wait for data to arrive and return what it
    /// receives. A non-blocking session will return immediately with an empty
    /// buffer. If a write is performed on a session with no room for more data,
    /// a blocking session will wait for room. A non-blocking session will
    /// return immediately without writing anything.
    pub fn set_blocking(&self, blocking: bool) {
        unsafe {
            raw::libssh2_session_set_blocking(self.raw, blocking as c_int)
        }
    }

    /// Returns whether the session was previously set to nonblocking.
    pub fn is_blocking(&self) -> bool {
        unsafe { raw::libssh2_session_get_blocking(self.raw) != 0 }
    }

    /// Set timeout for blocking functions.
    ///
    /// Set the timeout in milliseconds for how long a blocking the libssh2
    /// function calls may wait until they consider the situation an error and
    /// return an error.
    ///
    /// By default or if you set the timeout to zero, libssh2 has no timeout
    /// for blocking functions.
    pub fn set_timeout(&self, timeout_ms: u32) {
        let timeout_ms = timeout_ms as c_long;
        unsafe { raw::libssh2_session_set_timeout(self.raw, timeout_ms) }
    }

    /// Returns the timeout, in milliseconds, for how long blocking calls may
    /// wait until they time out.
    ///
    /// A timeout of 0 signifies no timeout.
    pub fn timeout(&self) -> u32 {
        unsafe { raw::libssh2_session_get_timeout(self.raw) as u32 }
    }

    /// Begin transport layer protocol negotiation with the connected host.
    ///
    /// This session does *not* take ownership of the socket provided, it is
    /// recommended to ensure that the socket persists the lifetime of this
    /// session to ensure that communication is correctly performed.
    ///
    /// It is also highly recommended that the stream provided is not used
    /// concurrently elsewhere for the duration of this session as it may
    /// interfere with the protocol.
    pub fn handshake(&mut self, stream: &TcpStream) -> Result<(), Error> {
        unsafe {
            return self.rc(handshake(self.raw, stream));
        }

        #[cfg(windows)]
        unsafe fn handshake(raw: *mut raw::LIBSSH2_SESSION, stream: &TcpStream)
                            -> libc::c_int {
            use std::os::windows::AsRawSocket;
            raw::libssh2_session_handshake(raw, stream.as_raw_socket())
        }

        #[cfg(unix)]
        unsafe fn handshake(raw: *mut raw::LIBSSH2_SESSION, stream: &TcpStream)
                            -> libc::c_int {
            use std::os::unix::AsRawFd;
            raw::libssh2_session_handshake(raw, stream.as_raw_fd())
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

    /// Attempt to perform SSH agent authentication.
    ///
    /// This is a helper method for attempting to authenticate the current
    /// connection with the first public key found in an SSH agent. If more
    /// control is needed than this method offers, it is recommended to use
    /// `agent` directly to control how the identity is found.
    pub fn userauth_agent(&self, username: &str) -> Result<(), Error> {
        let mut agent = try!(self.agent());
        try!(agent.connect());
        try!(agent.list_identities());
        let identity = match agent.identities().next() {
            Some(identity) => try!(identity),
            None => return Err(Error::new(raw::LIBSSH2_ERROR_INVAL as c_int,
                                          "no identities found in the ssh agent"))
        };
        agent.userauth(username, &identity)
    }

    /// Attempt public key authentication using a PEM encoded private key file
    /// stored on disk.
    pub fn userauth_pubkey_file(&self,
                                username: &str,
                                pubkey: Option<&Path>,
                                privatekey: &Path,
                                passphrase: Option<&str>) -> Result<(), Error> {
        let pubkey = pubkey.map(|s| CString::from_slice(s.as_vec()));
        let privatekey = CString::from_slice(privatekey.as_vec());
        let passphrase = passphrase.map(|s| CString::from_slice(s.as_bytes()));
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

    // Umm... I wish this were documented in libssh2?
    #[allow(missing_docs)]
    pub fn userauth_hostbased_file(&self,
                                   username: &str,
                                   publickey: &Path,
                                   privatekey: &Path,
                                   passphrase: Option<&str>,
                                   hostname: &str,
                                   local_username: Option<&str>)
                                   -> Result<(), Error> {
        let publickey = CString::from_slice(publickey.as_vec());
        let privatekey = CString::from_slice(privatekey.as_vec());
        let passphrase = passphrase.map(|s| CString::from_slice(s.as_bytes()));
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
    /// return an error. This case may be distinguished from a failing case by
    /// examining the return value of the `authenticated` method.
    ///
    /// The return value is a comma-separated string of supported auth schemes.
    pub fn auth_methods(&self, username: &str) -> Result<&str, Error> {
        let len = username.len();
        let username = CString::from_slice(username.as_bytes());
        unsafe {
            let ret = raw::libssh2_userauth_list(self.raw, username.as_ptr(),
                                                 len as c_uint);
            if ret.is_null() {
                Err(Error::last_error(self).unwrap())
            } else {
                Ok(str::from_utf8(::opt_bytes(self, ret).unwrap()).unwrap())
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
        let prefs = CString::from_slice(prefs.as_bytes());
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
        static STATIC: () = ();
        let method_type = method_type as c_int;
        let mut ret = Vec::new();
        unsafe {
            let mut ptr = 0 as *mut _;
            let rc = raw::libssh2_session_supported_algs(self.raw, method_type,
                                                         &mut ptr);
            if rc <= 0 { try!(self.rc(rc)) }
            for i in range(0, rc as isize) {
                let s = ::opt_bytes(&STATIC, *ptr.offset(i)).unwrap();;
                let s = str::from_utf8(s).unwrap();
                ret.push(s);
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
            SessionBinding::from_raw_opt(self, raw::libssh2_agent_init(self.raw))
        }
    }

    /// Init a collection of known hosts for this session.
    ///
    /// Returns the handle to an internal representation of a known host
    /// collection.
    pub fn known_hosts(&self) -> Result<KnownHosts, Error> {
        unsafe {
            let ptr = raw::libssh2_knownhost_init(self.raw);
            SessionBinding::from_raw_opt(self, ptr)
        }
    }

    /// Establish a new session-based channel.
    ///
    /// This method is commonly used to create a channel to execute commands
    /// over or create a new login shell.
    pub fn channel_session(&self) -> Result<Channel, Error> {
        self.channel_open("session",
                          raw::LIBSSH2_CHANNEL_WINDOW_DEFAULT as u32,
                          raw::LIBSSH2_CHANNEL_PACKET_DEFAULT as u32, None)
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
    ///
    /// The `Channel` returned represents a connection between this host and the
    /// specified remote host.
    pub fn channel_direct_tcpip(&self, host: &str, port: u16,
                                src: Option<(&str, u16)>)
                                -> Result<Channel, Error> {
        let (shost, sport) = src.unwrap_or(("127.0.0.1", 22));
        let host = CString::from_slice(host.as_bytes());
        let shost = CString::from_slice(shost.as_bytes());
        unsafe {
            let ret = raw::libssh2_channel_direct_tcpip_ex(self.raw,
                                                           host.as_ptr(),
                                                           port as c_int,
                                                           shost.as_ptr(),
                                                           sport as c_int);
            SessionBinding::from_raw_opt(self, ret)
        }
    }

    /// Instruct the remote SSH server to begin listening for inbound TCP/IP
    /// connections.
    ///
    /// New connections will be queued by the library until accepted by the
    /// `accept` method on the returned `Listener`.
    pub fn channel_forward_listen(&self,
                                  remote_port: u16,
                                  host: Option<&str>,
                                  queue_maxsize: Option<u32>)
                                  -> Result<(Listener, u16), Error> {
        let mut bound_port = 0;
        unsafe {
            let ret = raw::libssh2_channel_forward_listen_ex(
                            self.raw,
                            host.map(|s| s.as_ptr()).unwrap_or(0 as *const _)
                                as *mut _,
                            remote_port as c_int,
                            &mut bound_port,
                            queue_maxsize.unwrap_or(0) as c_int);
            SessionBinding::from_raw_opt(self, ret).map(|l| (l, bound_port as u16))
        }
    }

    /// Request a file from the remote host via SCP.
    ///
    /// The path specified is a path on the remote host which will attempt to be
    /// sent over the returned channel. Some stat information is also returned
    /// about the remote file to prepare for receiving the file.
    pub fn scp_recv(&self, path: &Path)
                    -> Result<(Channel, old_io::FileStat), Error> {
        let path = CString::from_slice(path.as_vec());
        unsafe {
            let mut sb: libc::stat = mem::zeroed();
            let ret = raw::libssh2_scp_recv(self.raw, path.as_ptr(), &mut sb);
            let mut c: Channel = try!(SessionBinding::from_raw_opt(self, ret));

            // Hm, apparently when we scp_recv() a file the actual channel
            // itself does not respond well to read_to_end(), and it also sends
            // an extra 0 byte (or so it seems). To work around this we
            // artificially limit the channel to a certain amount of bytes that
            // can be read.
            c.limit_read(sb.st_size as u64);
            Ok((c, mkstat(&sb)))
        }
    }

    /// Send a file to the remote host via SCP.
    ///
    /// The `remote_path` provided will the remote file name. The `times`
    /// argument is a tuple of (mtime, atime), and will default to the remote
    /// host's current time if not specified.
    ///
    /// The size of the file, `size`, must be known ahead of time before
    /// transmission.
    pub fn scp_send(&self, remote_path: &Path, mode: old_io::FilePermission,
                    size: u64, times: Option<(u64, u64)>)
                    -> Result<Channel, Error> {
        let path = CString::from_slice(remote_path.as_vec());
        let (mtime, atime) = times.unwrap_or((0, 0));
        unsafe {
            let ret = raw::libssh2_scp_send64(self.raw,
                                              path.as_ptr(),
                                              mode.bits() as c_int,
                                              size,
                                              mtime as libc::time_t,
                                              atime as libc::time_t);
            SessionBinding::from_raw_opt(self, ret)
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
            SessionBinding::from_raw_opt(self, ret)
        }
    }

    /// Allocate a new channel for exchanging data with the server.
    ///
    /// This is typically not called directly but rather through
    /// `channel_session`, `channel_direct_tcpip`, or `channel_forward_listen`.
    pub fn channel_open(&self, channel_type: &str,
                        window_size: u32, packet_size: u32,
                        message: Option<&str>) -> Result<Channel, Error> {
        let message_len = message.map(|s| s.len()).unwrap_or(0);
        unsafe {
            let ret = raw::libssh2_channel_open_ex(self.raw,
                                         channel_type.as_ptr() as *const _,
                                         channel_type.len() as c_uint,
                                         window_size as c_uint,
                                         packet_size as c_uint,
                                         message.as_ref().map(|s| s.as_ptr())
                                                .unwrap_or(0 as *const _)
                                                as *const _,
                                         message_len as c_uint);
            SessionBinding::from_raw_opt(self, ret)
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

    /// Get the remote key.
    ///
    /// Returns `None` if something went wrong.
    pub fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        let mut len = 0;
        let mut kind = 0;
        unsafe {
            let ret = raw::libssh2_session_hostkey(self.raw, &mut len, &mut kind);
            if ret.is_null() { return None }
            let data = slice::from_raw_parts(ret as *const u8, len as usize);
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
                Some(slice::from_raw_parts(ret, len))
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
    pub fn set_keepalive(&self, want_reply: bool, interval: u32)
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
    pub fn keepalive_send(&self) -> Result<u32, Error> {
        let mut ret = 0;
        let rc = unsafe { raw::libssh2_keepalive_send(self.raw, &mut ret) };
        try!(self.rc(rc));
        Ok(ret as u32)
    }

    /// Terminate the transport layer.
    ///
    /// Send a disconnect message to the remote host associated with session,
    /// along with a reason symbol and a verbose description.
    ///
    /// Note that this does *not* close the underlying socket.
    pub fn disconnect(&self,
                      reason: Option<DisconnectCode>,
                      description: &str,
                      lang: Option<&str>) -> Result<(), Error> {
        let reason = reason.unwrap_or(ByApplication) as c_int;
        let description = CString::from_slice(description.as_bytes());
        let lang = CString::from_slice(lang.unwrap_or("").as_bytes());
        unsafe {
            self.rc(raw::libssh2_session_disconnect_ex(self.raw,
                                                       reason,
                                                       description.as_ptr(),
                                                       lang.as_ptr()))
        }
    }

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

impl Binding for Session {
    type Raw = *mut raw::LIBSSH2_SESSION;

    unsafe fn from_raw(raw: *mut raw::LIBSSH2_SESSION) -> Session {
        Session { raw: raw }
    }
    fn raw(&self) -> *mut raw::LIBSSH2_SESSION { self.raw }
}

// Sure do wish this was exported in libnative!
fn mkstat(stat: &libc::stat) -> old_io::FileStat {
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

    old_io::FileStat {
        size: stat.st_size as u64,
        kind: match (stat.st_mode as Mode) & libc::S_IFMT {
            libc::S_IFREG => old_io::FileType::RegularFile,
            libc::S_IFDIR => old_io::FileType::Directory,
            libc::S_IFIFO => old_io::FileType::NamedPipe,
            libc::S_IFBLK => old_io::FileType::BlockSpecial,
            libc::S_IFLNK => old_io::FileType::Symlink,
            _ => old_io::FileType::Unknown,
        },
        perm: old_io::FilePermission::from_bits_truncate(stat.st_mode as u32),
        created: mktime(stat.st_ctime as u64, stat.st_ctime_nsec as u64),
        modified: mktime(stat.st_mtime as u64, stat.st_mtime_nsec as u64),
        accessed: mktime(stat.st_atime as u64, stat.st_atime_nsec as u64),
        unstable: old_io::UnstableFileStat {
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
