#[cfg(unix)]
use libc::size_t;
use libc::{self, c_char, c_int, c_long, c_uint, c_void};
use std::borrow::Cow;
use std::cell::{Ref, RefCell};
use std::ffi::CString;
use std::mem;
use std::net::TcpStream;
use std::path::Path;
use std::slice;
use std::str;
use std::sync::Arc;

use util;
use {raw, ByApplication, DisconnectCode, Error, HostKeyType};
use {Agent, Channel, HashType, KnownHosts, Listener, MethodType, Sftp};

/// Called by libssh2 to respond to some number of challenges as part of
/// keyboard interactive authentication.
pub trait KeyboardInteractivePrompt {
    /// `username` is the user name to be authenticated. It may not be the
    /// same as the username passed to `Session::userauth_keyboard_interactive`,
    /// and may be empty.
    /// `instructions` is some informational text to be displayed to the user.
    /// `prompts` is a series of prompts (or challenges) that must be responded
    /// to.
    /// The return value should be a Vec that holds one response for each prompt.
    fn prompt<'a>(
        &mut self,
        username: &str,
        instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String>;
}

/// A prompt/challenge returned as part of keyboard-interactive authentication
#[derive(Debug)]
pub struct Prompt<'a> {
    /// The label to show when prompting the user
    pub text: Cow<'a, str>,
    /// If true, the response that the user inputs should be displayed
    /// as they type.  If false then treat it as a password entry and
    /// do not display what is typed in response to this prompt.
    pub echo: bool,
}

/// This is a little helper function that is perhaps slightly overkill for the
/// current needs.
/// It saves the current sess->abstract pointer and replaces it with a
/// different values for the duration of the call to the supplied lambda.
/// When the lambda returns, the original abstract value is restored
/// and the result of the lambda is returned.
unsafe fn with_abstract<R, F: FnOnce() -> R>(
    sess: *mut raw::LIBSSH2_SESSION,
    new_value: *mut c_void,
    f: F,
) -> R {
    let abstrakt = raw::libssh2_session_abstract(sess);
    let old_value = *abstrakt;
    *abstrakt = new_value;
    let res = f();
    *abstrakt = old_value;
    res
}

pub(crate) struct SessionInner {
    pub(crate) raw: *mut raw::LIBSSH2_SESSION,
    tcp: RefCell<Option<TcpStream>>,
}

// The compiler doesn't know that it is Send safe because of the raw
// pointer inside.  We know that the way that it is used by libssh2
// and this crate is Send safe.
unsafe impl Send for SessionInner {}

/// An SSH session, typically representing one TCP connection.
///
/// All other structures are based on an SSH session and cannot outlive a
/// session. Sessions are created and then have the TCP socket handed to them
/// (via the `set_tcp_stream` method).
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

// The compiler doesn't know that it is Send safe because of the raw
// pointer inside.  We know that the way that it is used by libssh2
// and this crate is Send safe.
unsafe impl Send for Session {}

/// Metadata returned about a remote file when received via `scp`.
pub struct ScpFileStat {
    stat: libc::stat,
}

/// The io direction an application has to wait for in order not to block.
#[derive(Debug, PartialEq)]
pub enum BlockDirections {
    /// No direction blocked.
    None,
    /// Inbound direction blocked.
    Inbound,
    /// Outbound direction blockd.
    Outbound,
    /// Inbound and Outbound direction blocked.
    Both,
}

impl Session {
    /// Initializes an SSH session object.
    ///
    /// This function does not associate the session with a remote connection
    /// just yet. Various configuration options can be set such as the blocking
    /// mode, compression, sigpipe, the banner, etc. To associate this session
    /// with a TCP connection, use the `set_tcp_stream` method pass in an
    /// already-established TCP socket, and then follow up with a call to
    /// `handshake` to perform the ssh protocol handshake.
    pub fn new() -> Result<Session, Error> {
        ::init();
        unsafe {
            let ret = raw::libssh2_session_init_ex(None, None, None, 0 as *mut _);
            if ret.is_null() {
                Err(Error::unknown())
            } else {
                Ok(Session {
                    inner: Arc::new(SessionInner {
                        raw: ret,
                        tcp: RefCell::new(None),
                    }),
                })
            }
        }
    }

    #[doc(hidden)]
    pub fn raw(&self) -> *mut raw::LIBSSH2_SESSION {
        self.inner.raw
    }

    /// Set the SSH protocol banner for the local client
    ///
    /// Set the banner that will be sent to the remote host when the SSH session
    /// is started with handshake(). This is optional; a banner
    /// corresponding to the protocol and libssh2 version will be sent by
    /// default.
    pub fn set_banner(&self, banner: &str) -> Result<(), Error> {
        let banner = CString::new(banner)?;
        unsafe {
            self.rc(raw::libssh2_session_banner_set(
                self.inner.raw,
                banner.as_ptr(),
            ))
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
            self.rc(raw::libssh2_session_flag(
                self.inner.raw,
                raw::LIBSSH2_FLAG_SIGPIPE as c_int,
                block as c_int,
            ))
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
            self.rc(raw::libssh2_session_flag(
                self.inner.raw,
                raw::LIBSSH2_FLAG_COMPRESS as c_int,
                compress as c_int,
            ))
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
        unsafe { raw::libssh2_session_set_blocking(self.inner.raw, blocking as c_int) }
    }

    /// Returns whether the session was previously set to nonblocking.
    pub fn is_blocking(&self) -> bool {
        unsafe { raw::libssh2_session_get_blocking(self.inner.raw) != 0 }
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
        unsafe { raw::libssh2_session_set_timeout(self.inner.raw, timeout_ms) }
    }

    /// Returns the timeout, in milliseconds, for how long blocking calls may
    /// wait until they time out.
    ///
    /// A timeout of 0 signifies no timeout.
    pub fn timeout(&self) -> u32 {
        unsafe { raw::libssh2_session_get_timeout(self.inner.raw) as u32 }
    }

    /// Begin transport layer protocol negotiation with the connected host.
    ///
    /// You must call this after associating the session with a tcp stream
    /// via the `set_tcp_stream` function.
    pub fn handshake(&mut self) -> Result<(), Error> {
        #[cfg(windows)]
        unsafe fn handshake(raw: *mut raw::LIBSSH2_SESSION, stream: &TcpStream) -> libc::c_int {
            use std::os::windows::prelude::*;
            raw::libssh2_session_handshake(raw, stream.as_raw_socket())
        }

        #[cfg(unix)]
        unsafe fn handshake(raw: *mut raw::LIBSSH2_SESSION, stream: &TcpStream) -> libc::c_int {
            use std::os::unix::prelude::*;
            raw::libssh2_session_handshake(raw, stream.as_raw_fd())
        }

        unsafe {
            let stream = self.inner.tcp.borrow();

            let stream = stream.as_ref().ok_or_else(|| {
                Error::new(
                    raw::LIBSSH2_ERROR_BAD_SOCKET,
                    "use set_tcp_stream() to associate with a TcpStream",
                )
            })?;

            self.rc(handshake(self.inner.raw, stream))
        }
    }

    /// The session takes ownership of the socket provided.
    /// You may use the tcp_stream() method to obtain a reference
    /// to it later.
    ///
    /// It is also highly recommended that the stream provided is not used
    /// concurrently elsewhere for the duration of this session as it may
    /// interfere with the protocol.
    pub fn set_tcp_stream(&mut self, stream: TcpStream) {
        *self.inner.tcp.borrow_mut() = Some(stream);
    }

    /// Returns a reference to the stream that was associated with the Session
    /// by the Session::handshake method.
    pub fn tcp_stream(&self) -> Ref<Option<TcpStream>> {
        self.inner.tcp.borrow()
    }

    /// Attempt basic password authentication.
    ///
    /// Note that many SSH servers which appear to support ordinary password
    /// authentication actually have it disabled and use Keyboard Interactive
    /// authentication (routed via PAM or another authentication backed)
    /// instead.
    pub fn userauth_password(&self, username: &str, password: &str) -> Result<(), Error> {
        self.rc(unsafe {
            raw::libssh2_userauth_password_ex(
                self.inner.raw,
                username.as_ptr() as *const _,
                username.len() as c_uint,
                password.as_ptr() as *const _,
                password.len() as c_uint,
                None,
            )
        })
    }

    /// Attempt keyboard interactive authentication.
    ///
    /// You must supply a callback function to
    pub fn userauth_keyboard_interactive<P: KeyboardInteractivePrompt>(
        &self,
        username: &str,
        prompter: &mut P,
    ) -> Result<(), Error> {
        // hold on to your hats, this is a bit involved.
        // The keyboard interactive callback is a bit tricksy, and we want to wrap the
        // raw C types with something a bit safer and more ergonomic.
        // Since the interface is defined in terms of a simple function pointer, wrapping
        // is a bit awkward.
        //
        // The session struct has an abstrakt pointer reserved for
        // the user of the embedding application, and that pointer is passed to the
        // prompt callback. We can use this to store a pointer to some state so that
        // we can manage the conversion.
        //
        // The prompts and responses are defined to be UTF-8, but we use from_utf8_lossy
        // to avoid panics in case the server isn't conformant for whatever reason.
        extern "C" fn prompt<P: KeyboardInteractivePrompt>(
            username: *const c_char,
            username_len: c_int,
            instruction: *const c_char,
            instruction_len: c_int,
            num_prompts: c_int,
            prompts: *const raw::LIBSSH2_USERAUTH_KBDINT_PROMPT,
            responses: *mut raw::LIBSSH2_USERAUTH_KBDINT_RESPONSE,
            abstrakt: *mut *mut c_void,
        ) {
            use std::panic::{catch_unwind, AssertUnwindSafe};
            // Catch panics; we can't let them unwind to C code.
            // There's not much to be done with them though because the
            // signature of the callback doesn't allow reporting an error.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let prompter = unsafe { &mut **(abstrakt as *mut *mut P) };

                let username =
                    unsafe { slice::from_raw_parts(username as *const u8, username_len as usize) };
                let username = String::from_utf8_lossy(username);

                let instruction = unsafe {
                    slice::from_raw_parts(instruction as *const u8, instruction_len as usize)
                };
                let instruction = String::from_utf8_lossy(instruction);

                let prompts = unsafe { slice::from_raw_parts(prompts, num_prompts as usize) };
                let responses =
                    unsafe { slice::from_raw_parts_mut(responses, num_prompts as usize) };

                let prompts: Vec<Prompt> = prompts
                    .iter()
                    .map(|item| {
                        let data = unsafe {
                            slice::from_raw_parts(item.text as *const u8, item.length as usize)
                        };
                        Prompt {
                            text: String::from_utf8_lossy(data),
                            echo: item.echo != 0,
                        }
                    })
                    .collect();

                // libssh2 wants to be able to free(3) the response strings, so allocate
                // storage and copy the responses into appropriately owned memory.
                // We can't simply call strdup(3) here because the rust string types
                // are not NUL terminated.
                fn strdup_string(s: &str) -> *mut c_char {
                    let len = s.len();
                    let ptr = unsafe { libc::malloc(len + 1) as *mut c_char };
                    if !ptr.is_null() {
                        unsafe {
                            ::std::ptr::copy_nonoverlapping(
                                s.as_bytes().as_ptr() as *const c_char,
                                ptr,
                                len,
                            );
                            *ptr.offset(len as isize) = 0;
                        }
                    }
                    ptr
                }

                for (i, response) in (*prompter)
                    .prompt(&username, &instruction, &prompts)
                    .into_iter()
                    .take(prompts.len())
                    .enumerate()
                {
                    let ptr = strdup_string(&response);
                    if !ptr.is_null() {
                        responses[i].length = response.len() as c_uint;
                    } else {
                        responses[i].length = 0;
                    }
                    responses[i].text = ptr;
                }
            }));
        }

        unsafe {
            with_abstract(self.inner.raw, prompter as *mut P as *mut c_void, || {
                self.rc(raw::libssh2_userauth_keyboard_interactive_ex(
                    self.inner.raw,
                    username.as_ptr() as *const _,
                    username.len() as c_uint,
                    Some(prompt::<P>),
                ))
            })
        }
    }

    /// Attempt to perform SSH agent authentication.
    ///
    /// This is a helper method for attempting to authenticate the current
    /// connection with the first public key found in an SSH agent. If more
    /// control is needed than this method offers, it is recommended to use
    /// `agent` directly to control how the identity is found.
    pub fn userauth_agent(&self, username: &str) -> Result<(), Error> {
        let mut agent = self.agent()?;
        agent.connect()?;
        agent.list_identities()?;
        let identity = match agent.identities().next() {
            Some(identity) => identity?,
            None => {
                return Err(Error::new(
                    raw::LIBSSH2_ERROR_INVAL as c_int,
                    "no identities found in the ssh agent",
                ))
            }
        };
        agent.userauth(username, &identity)
    }

    /// Attempt public key authentication using a PEM encoded private key file
    /// stored on disk.
    pub fn userauth_pubkey_file(
        &self,
        username: &str,
        pubkey: Option<&Path>,
        privatekey: &Path,
        passphrase: Option<&str>,
    ) -> Result<(), Error> {
        let pubkey = match pubkey {
            Some(s) => Some(CString::new(util::path2bytes(s)?)?),
            None => None,
        };
        let privatekey = CString::new(util::path2bytes(privatekey)?)?;
        let passphrase = match passphrase {
            Some(s) => Some(CString::new(s)?),
            None => None,
        };
        self.rc(unsafe {
            raw::libssh2_userauth_publickey_fromfile_ex(
                self.inner.raw,
                username.as_ptr() as *const _,
                username.len() as c_uint,
                pubkey.as_ref().map(|s| s.as_ptr()).unwrap_or(0 as *const _),
                privatekey.as_ptr(),
                passphrase
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(0 as *const _),
            )
        })
    }

    /// Attempt public key authentication using a PEM encoded private key from
    /// memory. Public key is computed from private key if none passed.
    /// This is available only for `unix` targets, as it relies on openssl.
    /// It is therefore recommended to use `#[cfg(unix)]` or otherwise test for
    /// the `unix` compliation target when using this function.
    #[cfg(unix)]
    pub fn userauth_pubkey_memory(
        &self,
        username: &str,
        pubkeydata: Option<&str>,
        privatekeydata: &str,
        passphrase: Option<&str>,
    ) -> Result<(), Error> {
        let (pubkeydata, pubkeydata_len) = match pubkeydata {
            Some(s) => (Some(CString::new(s)?), s.len()),
            None => (None, 0),
        };
        let privatekeydata_len = privatekeydata.len();
        let privatekeydata = CString::new(privatekeydata)?;
        let passphrase = match passphrase {
            Some(s) => Some(CString::new(s)?),
            None => None,
        };
        self.rc(unsafe {
            raw::libssh2_userauth_publickey_frommemory(
                self.inner.raw,
                username.as_ptr() as *const _,
                username.len() as size_t,
                pubkeydata
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(0 as *const _),
                pubkeydata_len as size_t,
                privatekeydata.as_ptr(),
                privatekeydata_len as size_t,
                passphrase
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(0 as *const _),
            )
        })
    }

    // Umm... I wish this were documented in libssh2?
    #[allow(missing_docs)]
    pub fn userauth_hostbased_file(
        &self,
        username: &str,
        publickey: &Path,
        privatekey: &Path,
        passphrase: Option<&str>,
        hostname: &str,
        local_username: Option<&str>,
    ) -> Result<(), Error> {
        let publickey = CString::new(util::path2bytes(publickey)?)?;
        let privatekey = CString::new(util::path2bytes(privatekey)?)?;
        let passphrase = match passphrase {
            Some(s) => Some(CString::new(s)?),
            None => None,
        };
        let local_username = match local_username {
            Some(local) => local,
            None => username,
        };
        self.rc(unsafe {
            raw::libssh2_userauth_hostbased_fromfile_ex(
                self.inner.raw,
                username.as_ptr() as *const _,
                username.len() as c_uint,
                publickey.as_ptr(),
                privatekey.as_ptr(),
                passphrase
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(0 as *const _),
                hostname.as_ptr() as *const _,
                hostname.len() as c_uint,
                local_username.as_ptr() as *const _,
                local_username.len() as c_uint,
            )
        })
    }

    /// Indicates whether or not the named session has been successfully
    /// authenticated.
    pub fn authenticated(&self) -> bool {
        unsafe { raw::libssh2_userauth_authenticated(self.inner.raw) != 0 }
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
    /// The return value is a comma-separated string of supported auth schemes,
    /// and may be an empty string.
    pub fn auth_methods(&self, username: &str) -> Result<&str, Error> {
        let len = username.len();
        let username = CString::new(username)?;
        unsafe {
            let ret = raw::libssh2_userauth_list(self.inner.raw, username.as_ptr(), len as c_uint);
            if ret.is_null() {
                match Error::last_error(self) {
                    Some(err) => Err(err),
                    None => Ok(""),
                }
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
    pub fn method_pref(&self, method_type: MethodType, prefs: &str) -> Result<(), Error> {
        let prefs = CString::new(prefs)?;
        unsafe {
            self.rc(raw::libssh2_session_method_pref(
                self.inner.raw,
                method_type as c_int,
                prefs.as_ptr(),
            ))
        }
    }

    /// Return the currently active algorithms.
    ///
    /// Returns the actual method negotiated for a particular transport
    /// parameter. May return `None` if the session has not yet been started.
    pub fn methods(&self, method_type: MethodType) -> Option<&str> {
        unsafe {
            let ptr = raw::libssh2_session_methods(self.inner.raw, method_type as c_int);
            ::opt_bytes(self, ptr).and_then(|s| str::from_utf8(s).ok())
        }
    }

    /// Get list of supported algorithms.
    pub fn supported_algs(&self, method_type: MethodType) -> Result<Vec<&'static str>, Error> {
        static STATIC: () = ();
        let method_type = method_type as c_int;
        let mut ret = Vec::new();
        unsafe {
            let mut ptr = 0 as *mut _;
            let rc = raw::libssh2_session_supported_algs(self.inner.raw, method_type, &mut ptr);
            if rc <= 0 {
                self.rc(rc)?;
            }
            for i in 0..(rc as isize) {
                let s = ::opt_bytes(&STATIC, *ptr.offset(i)).unwrap();
                let s = str::from_utf8(s).unwrap();
                ret.push(s);
            }
            raw::libssh2_free(self.inner.raw, ptr as *mut c_void);
        }
        Ok(ret)
    }

    /// Init an ssh-agent handle.
    ///
    /// The returned agent will still need to be connected manually before use.
    pub fn agent(&self) -> Result<Agent, Error> {
        unsafe { Agent::from_raw_opt(raw::libssh2_agent_init(self.inner.raw), &self.inner) }
    }

    /// Init a collection of known hosts for this session.
    ///
    /// Returns the handle to an internal representation of a known host
    /// collection.
    pub fn known_hosts(&self) -> Result<KnownHosts, Error> {
        unsafe {
            let ptr = raw::libssh2_knownhost_init(self.inner.raw);
            KnownHosts::from_raw_opt(ptr, &self.inner)
        }
    }

    /// Establish a new session-based channel.
    ///
    /// This method is commonly used to create a channel to execute commands
    /// over or create a new login shell.
    pub fn channel_session(&self) -> Result<Channel, Error> {
        self.channel_open(
            "session",
            raw::LIBSSH2_CHANNEL_WINDOW_DEFAULT as u32,
            raw::LIBSSH2_CHANNEL_PACKET_DEFAULT as u32,
            None,
        )
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
    pub fn channel_direct_tcpip(
        &self,
        host: &str,
        port: u16,
        src: Option<(&str, u16)>,
    ) -> Result<Channel, Error> {
        let (shost, sport) = src.unwrap_or(("127.0.0.1", 22));
        let host = CString::new(host)?;
        let shost = CString::new(shost)?;
        unsafe {
            let ret = raw::libssh2_channel_direct_tcpip_ex(
                self.inner.raw,
                host.as_ptr(),
                port as c_int,
                shost.as_ptr(),
                sport as c_int,
            );
            Channel::from_raw_opt(ret, &self.inner)
        }
    }

    /// Instruct the remote SSH server to begin listening for inbound TCP/IP
    /// connections.
    ///
    /// New connections will be queued by the library until accepted by the
    /// `accept` method on the returned `Listener`.
    pub fn channel_forward_listen(
        &self,
        remote_port: u16,
        host: Option<&str>,
        queue_maxsize: Option<u32>,
    ) -> Result<(Listener, u16), Error> {
        let mut bound_port = 0;
        unsafe {
            let ret = raw::libssh2_channel_forward_listen_ex(
                self.inner.raw,
                host.map(|s| s.as_ptr()).unwrap_or(0 as *const _) as *mut _,
                remote_port as c_int,
                &mut bound_port,
                queue_maxsize.unwrap_or(0) as c_int,
            );
            Listener::from_raw_opt(ret, &self.inner).map(|l| (l, bound_port as u16))
        }
    }

    /// Request a file from the remote host via SCP.
    ///
    /// The path specified is a path on the remote host which will attempt to be
    /// sent over the returned channel. Some stat information is also returned
    /// about the remote file to prepare for receiving the file.
    pub fn scp_recv(&self, path: &Path) -> Result<(Channel, ScpFileStat), Error> {
        let path = CString::new(util::path2bytes(path)?)?;
        unsafe {
            let mut sb: raw::libssh2_struct_stat = mem::zeroed();
            let ret = raw::libssh2_scp_recv2(self.inner.raw, path.as_ptr(), &mut sb);
            let mut c = Channel::from_raw_opt(ret, &self.inner)?;

            // Hm, apparently when we scp_recv() a file the actual channel
            // itself does not respond well to read_to_end(), and it also sends
            // an extra 0 byte (or so it seems). To work around this we
            // artificially limit the channel to a certain amount of bytes that
            // can be read.
            c.limit_read(sb.st_size as u64);
            Ok((c, ScpFileStat { stat: *sb }))
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
    pub fn scp_send(
        &self,
        remote_path: &Path,
        mode: i32,
        size: u64,
        times: Option<(u64, u64)>,
    ) -> Result<Channel, Error> {
        let path = CString::new(util::path2bytes(remote_path)?)?;
        let (mtime, atime) = times.unwrap_or((0, 0));
        unsafe {
            let ret = raw::libssh2_scp_send64(
                self.inner.raw,
                path.as_ptr(),
                mode as c_int,
                size as i64,
                mtime as libc::time_t,
                atime as libc::time_t,
            );
            Channel::from_raw_opt(ret, &self.inner)
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
            let ret = raw::libssh2_sftp_init(self.inner.raw);
            Sftp::from_raw_opt(ret, &self.inner)
        }
    }

    /// Allocate a new channel for exchanging data with the server.
    ///
    /// This is typically not called directly but rather through
    /// `channel_session`, `channel_direct_tcpip`, or `channel_forward_listen`.
    pub fn channel_open(
        &self,
        channel_type: &str,
        window_size: u32,
        packet_size: u32,
        message: Option<&str>,
    ) -> Result<Channel, Error> {
        let message_len = message.map(|s| s.len()).unwrap_or(0);
        unsafe {
            let ret = raw::libssh2_channel_open_ex(
                self.inner.raw,
                channel_type.as_ptr() as *const _,
                channel_type.len() as c_uint,
                window_size as c_uint,
                packet_size as c_uint,
                message
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(0 as *const _) as *const _,
                message_len as c_uint,
            );
            Channel::from_raw_opt(ret, &self.inner)
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
        unsafe { ::opt_bytes(self, raw::libssh2_session_banner_get(self.inner.raw)) }
    }

    /// Get the remote key.
    ///
    /// Returns `None` if something went wrong.
    pub fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        let mut len = 0;
        let mut kind = 0;
        unsafe {
            let ret = raw::libssh2_session_hostkey(self.inner.raw, &mut len, &mut kind);
            if ret.is_null() {
                return None;
            }
            let data = slice::from_raw_parts(ret as *const u8, len as usize);
            let kind = match kind {
                raw::LIBSSH2_HOSTKEY_TYPE_RSA => HostKeyType::Rsa,
                raw::LIBSSH2_HOSTKEY_TYPE_DSS => HostKeyType::Dss,
                raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_256 => HostKeyType::Ecdsa256,
                raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_384 => HostKeyType::Ecdsa384,
                raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_521 => HostKeyType::Ecdsa521,
                raw::LIBSSH2_HOSTKEY_TYPE_ED25519 => HostKeyType::Ed255219,
                raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN => HostKeyType::Unknown,
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
            HashType::Sha256 => 32,
        };
        unsafe {
            let ret = raw::libssh2_hostkey_hash(self.inner.raw, hash as c_int);
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
    pub fn set_keepalive(&self, want_reply: bool, interval: u32) {
        unsafe {
            raw::libssh2_keepalive_config(self.inner.raw, want_reply as c_int, interval as c_uint)
        }
    }

    /// Send a keepalive message if needed.
    ///
    /// Returns how many seconds you can sleep after this call before you need
    /// to call it again.
    pub fn keepalive_send(&self) -> Result<u32, Error> {
        let mut ret = 0;
        let rc = unsafe { raw::libssh2_keepalive_send(self.inner.raw, &mut ret) };
        self.rc(rc)?;
        Ok(ret as u32)
    }

    /// Terminate the transport layer.
    ///
    /// Send a disconnect message to the remote host associated with session,
    /// along with a reason symbol and a verbose description.
    ///
    /// Note that this does *not* close the underlying socket.
    pub fn disconnect(
        &self,
        reason: Option<DisconnectCode>,
        description: &str,
        lang: Option<&str>,
    ) -> Result<(), Error> {
        let reason = reason.unwrap_or(ByApplication) as c_int;
        let description = CString::new(description)?;
        let lang = CString::new(lang.unwrap_or(""))?;
        unsafe {
            self.rc(raw::libssh2_session_disconnect_ex(
                self.inner.raw,
                reason,
                description.as_ptr(),
                lang.as_ptr(),
            ))
        }
    }

    /// Translate a return code into a Rust-`Result`.
    pub fn rc(&self, rc: c_int) -> Result<(), Error> {
        self.inner.rc(rc)
    }

    /// Returns the blocked io directions that the application needs to wait for.
    ///
    /// This function should be used after an error of type `WouldBlock` is returned to
    /// find out the socket events the application has to wait for.
    pub fn block_directions(&self) -> BlockDirections {
        let dir = unsafe { raw::libssh2_session_block_directions(self.inner.raw) };
        match dir {
            raw::LIBSSH2_SESSION_BLOCK_INBOUND => BlockDirections::Inbound,
            raw::LIBSSH2_SESSION_BLOCK_OUTBOUND => BlockDirections::Outbound,
            x if x == raw::LIBSSH2_SESSION_BLOCK_INBOUND | raw::LIBSSH2_SESSION_BLOCK_OUTBOUND => {
                BlockDirections::Both
            }
            _ => BlockDirections::None,
        }
    }
}

impl SessionInner {
    /// Translate a return code into a Rust-`Result`.
    pub fn rc(&self, rc: c_int) -> Result<(), Error> {
        if rc >= 0 {
            Ok(())
        } else {
            Err(Error::from_session_error_raw(self.raw, rc))
        }
    }
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        unsafe {
            let _rc = raw::libssh2_session_free(self.raw);
        }
    }
}

impl ScpFileStat {
    /// Returns the size of the remote file.
    pub fn size(&self) -> u64 {
        self.stat.st_size as u64
    }
    /// Returns the listed mode of the remote file.
    pub fn mode(&self) -> i32 {
        self.stat.st_mode as i32
    }
    /// Returns whether the remote file is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode() & (libc::S_IFMT as i32) == (libc::S_IFDIR as i32)
    }
    /// Returns whether the remote file is a regular file.
    pub fn is_file(&self) -> bool {
        self.mode() & (libc::S_IFMT as i32) == (libc::S_IFREG as i32)
    }
}
