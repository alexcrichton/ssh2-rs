#![feature(phase)]
#![allow(bad_style)]

extern crate libc;
#[phase(plugin)]
extern crate "link-config" as link_conifg;

use libc::{c_int, size_t, c_void, c_char, c_long, c_uchar, c_uint};

pub static SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: c_int = 1;
pub static SSH_DISCONNECT_PROTOCOL_ERROR: c_int = 2;
pub static SSH_DISCONNECT_KEY_EXCHANGE_FAILED: c_int = 3;
pub static SSH_DISCONNECT_RESERVED: c_int = 4;
pub static SSH_DISCONNECT_MAC_ERROR: c_int = 5;
pub static SSH_DISCONNECT_COMPRESSION_ERROR: c_int = 6;
pub static SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: c_int = 7;
pub static SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: c_int = 8;
pub static SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: c_int = 9;
pub static SSH_DISCONNECT_CONNECTION_LOST: c_int = 10;
pub static SSH_DISCONNECT_BY_APPLICATION: c_int = 11;
pub static SSH_DISCONNECT_TOO_MANY_CONNECTIONS: c_int = 12;
pub static SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: c_int = 13;
pub static SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: c_int = 14;
pub static SSH_DISCONNECT_ILLEGAL_USER_NAME: c_int = 15;

pub static LIBSSH2_FLAG_SIGPIPE: c_int = 1;
pub static LIBSSH2_FLAG_COMPRESS: c_int = 2;

pub static LIBSSH2_HOSTKEY_TYPE_UNKNOWN: c_int = 0;
pub static LIBSSH2_HOSTKEY_TYPE_RSA: c_int = 1;
pub static LIBSSH2_HOSTKEY_TYPE_DSS: c_int = 2;

pub static LIBSSH2_METHOD_KEX: c_int = 0;
pub static LIBSSH2_METHOD_HOSTKEY: c_int = 1;
pub static LIBSSH2_METHOD_CRYPT_CS: c_int = 2;
pub static LIBSSH2_METHOD_CRYPT_SC: c_int = 3;
pub static LIBSSH2_METHOD_MAC_CS: c_int = 4;
pub static LIBSSH2_METHOD_MAC_SC: c_int = 5;
pub static LIBSSH2_METHOD_COMP_CS: c_int = 6;
pub static LIBSSH2_METHOD_COMP_SC: c_int = 7;
pub static LIBSSH2_METHOD_LANG_CS: c_int = 8;
pub static LIBSSH2_METHOD_LANG_SC: c_int = 9;

pub static LIBSSH2_CHANNEL_PACKET_DEFAULT: c_uint = 32768;
pub static LIBSSH2_CHANNEL_WINDOW_DEFAULT: c_uint = 2 * 1024 * 1024;

pub enum LIBSSH2_SESSION {}
pub enum LIBSSH2_AGENT {}
pub enum LIBSSH2_CHANNEL {}

#[repr(C)]
pub struct libssh2_agent_publickey {
    pub magic: c_uint,
    pub node: *mut c_void,
    pub blob: *mut c_uchar,
    pub blob_len: size_t,
    pub comment: *const c_char,
}

pub type LIBSSH2_ALLOC_FUNC = extern fn(size_t, *mut *mut c_void) -> *mut c_void;
pub type LIBSSH2_FREE_FUNC = extern fn(*mut c_void, *mut *mut c_void);
pub type LIBSSH2_REALLOC_FUNC = extern fn(*mut c_void, size_t, *mut *mut c_void)
                                          -> *mut c_void;

#[cfg(unix)]    pub type libssh2_socket_t = c_int;
#[cfg(windows)] pub type libssh2_socket_t = libc::SOCKET;

#[cfg(unix)]
link_config!("libssh2", ["favor_static"])

#[cfg(unix)]
#[link(name = "z")]
extern {}

#[cfg(windows)]
#[link(name = "ws2_32")]  // needed by ssh2
#[link(name = "bcrypt")]  // needed by ssh2
#[link(name = "crypt32")] // needed by ssh2
#[link(name = "ssh2", kind = "static")]
extern {}

extern {
    // misc
    pub fn libssh2_init(flag: c_int) -> c_int;
    pub fn libssh2_exit();
    pub fn libssh2_free(sess: *mut LIBSSH2_SESSION, ptr: *mut c_void);

    // session
    pub fn libssh2_session_init_ex(alloc: Option<LIBSSH2_ALLOC_FUNC>,
                                   free: Option<LIBSSH2_FREE_FUNC>,
                                   realloc: Option<LIBSSH2_REALLOC_FUNC>)
                                   -> *mut LIBSSH2_SESSION;
    pub fn libssh2_session_free(sess: *mut LIBSSH2_SESSION) -> c_int;
    pub fn libssh2_session_banner_get(sess: *mut LIBSSH2_SESSION) -> *const c_char;
    pub fn libssh2_session_banner_set(sess: *mut LIBSSH2_SESSION,
                                      banner: *const c_char) -> c_int;
    pub fn libssh2_session_disconnect_ex(sess: *mut LIBSSH2_SESSION,
                                         reason: c_int,
                                         description: *const c_char,
                                         lang: *const c_char) -> c_int;
    pub fn libssh2_session_flag(sess: *mut LIBSSH2_SESSION,
                                flag: c_int, value: c_int) -> c_int;
    pub fn libssh2_session_get_blocking(session: *mut LIBSSH2_SESSION) -> c_int;
    pub fn libssh2_session_get_timeout(sess: *mut LIBSSH2_SESSION) -> c_long;
    pub fn libssh2_session_hostkey(sess: *mut LIBSSH2_SESSION,
                                   len: *mut size_t,
                                   kind: *mut c_int) -> *const c_char;
    pub fn libssh2_session_method_pref(sess: *mut LIBSSH2_SESSION,
                                       method_type: c_int,
                                       prefs: *const c_char) -> c_int;
    pub fn libssh2_session_methods(sess: *mut LIBSSH2_SESSION,
                                   method_type: c_int) -> *const c_char;
    pub fn libssh2_session_set_blocking(session: *mut LIBSSH2_SESSION,
                                        blocking: c_int);
    pub fn libssh2_session_set_timeout(session: *mut LIBSSH2_SESSION,
                                       timeout: c_long);
    pub fn libssh2_session_supported_algs(session: *mut LIBSSH2_SESSION,
                                          method_type: c_int,
                                          algs: *mut *mut *const c_char) -> c_int;
    pub fn libssh2_session_last_error(sess: *mut LIBSSH2_SESSION,
                                      msg: *mut *mut c_char,
                                      len: *mut c_int,
                                      want_buf: c_int) -> c_int;
    pub fn libssh2_session_handshake(sess: *mut LIBSSH2_SESSION,
                                     socket: libssh2_socket_t) -> c_int;

    // agent
    pub fn libssh2_agent_init(sess: *mut LIBSSH2_SESSION) -> *mut LIBSSH2_AGENT;
    pub fn libssh2_agent_free(agent: *mut LIBSSH2_AGENT);
    pub fn libssh2_agent_connect(agent: *mut LIBSSH2_AGENT) -> c_int;
    pub fn libssh2_agent_disconnect(agent: *mut LIBSSH2_AGENT) -> c_int;
    pub fn libssh2_agent_list_identities(agent: *mut LIBSSH2_AGENT) -> c_int;
    pub fn libssh2_agent_get_identity(agent: *mut LIBSSH2_AGENT,
                                      store: *mut *mut libssh2_agent_publickey,
                                      prev: *mut libssh2_agent_publickey)
                                      -> c_int;
    pub fn libssh2_agent_userauth(agent: *mut LIBSSH2_AGENT,
                                  username: *const c_char,
                                  identity: *mut libssh2_agent_publickey) -> c_int;

    // channels
    pub fn libssh2_channel_free(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_close(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_wait_closed(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_wait_eof(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_eof(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_process_startup(chan: *mut LIBSSH2_CHANNEL,
                                           req: *const c_char,
                                           req_len: c_uint,
                                           msg: *const c_char,
                                           msg_len: c_uint) -> c_int;
    pub fn libssh2_channel_flush_ex(chan: *mut LIBSSH2_CHANNEL,
                                    streamid: c_int) -> c_int;
    pub fn libssh2_channel_write_ex(chan: *mut LIBSSH2_CHANNEL,
                                    stream_id: c_int,
                                    buf: *mut c_char,
                                    buflen: size_t) -> c_int;
    pub fn libssh2_channel_get_exit_signal(chan: *mut LIBSSH2_CHANNEL,
                                           exitsignal: *mut *mut c_char,
                                           exitsignal_len: *mut size_t,
                                           errmsg: *mut *mut c_char,
                                           errmsg_len: *mut size_t,
                                           langtag: *mut *mut c_char,
                                           langtag_len: *mut size_t) -> c_int;
    pub fn libssh2_channel_get_exit_status(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_open_ex(sess: *mut LIBSSH2_SESSION,
                                   channel_type: *const c_char,
                                   channel_type_len: c_uint,
                                   window_size: c_uint,
                                   packet_size: c_uint,
                                   message: *const c_char,
                                   message_len: c_uint) -> *mut LIBSSH2_CHANNEL;

    // userauth
    pub fn libssh2_userauth_authenticated(sess: *mut LIBSSH2_SESSION) -> c_int;
    pub fn libssh2_userauth_list(sess: *mut LIBSSH2_SESSION,
                                 username: *const c_char,
                                 username_len: c_uint) -> *const c_char;
}
