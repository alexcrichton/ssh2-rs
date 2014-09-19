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

pub static LIBSSH2_ERROR_BANNER_RECV: c_int = -2;
pub static LIBSSH2_ERROR_BANNER_SEND: c_int = -3;
pub static LIBSSH2_ERROR_INVALID_MAC: c_int = -4;
pub static LIBSSH2_ERROR_KEX_FAILURE: c_int = -5;
pub static LIBSSH2_ERROR_ALLOC: c_int = -6;
pub static LIBSSH2_ERROR_SOCKET_SEND: c_int = -7;
pub static LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE: c_int = -8;
pub static LIBSSH2_ERROR_TIMEOUT: c_int = -9;
pub static LIBSSH2_ERROR_HOSTKEY_INIT: c_int = -10;
pub static LIBSSH2_ERROR_HOSTKEY_SIGN: c_int = -11;
pub static LIBSSH2_ERROR_DECRYPT: c_int = -12;
pub static LIBSSH2_ERROR_SOCKET_DISCONNECT: c_int = -13;
pub static LIBSSH2_ERROR_PROTO: c_int = -14;
pub static LIBSSH2_ERROR_PASSWORD_EXPIRED: c_int = -15;
pub static LIBSSH2_ERROR_FILE: c_int = -16;
pub static LIBSSH2_ERROR_METHOD_NONE: c_int = -17;
pub static LIBSSH2_ERROR_AUTHENTICATION_FAILED: c_int = -18;
pub static LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED: c_int =
                LIBSSH2_ERROR_AUTHENTICATION_FAILED;
pub static LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED: c_int = -19;
pub static LIBSSH2_ERROR_CHANNEL_OUTOFORDER: c_int = -20;
pub static LIBSSH2_ERROR_CHANNEL_FAILURE: c_int = -21;
pub static LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED: c_int = -22;
pub static LIBSSH2_ERROR_CHANNEL_UNKNOWN: c_int = -23;
pub static LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED: c_int = -24;
pub static LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED: c_int = -25;
pub static LIBSSH2_ERROR_CHANNEL_CLOSED: c_int = -26;
pub static LIBSSH2_ERROR_CHANNEL_EOF_SENT: c_int = -27;
pub static LIBSSH2_ERROR_SCP_PROTOCOL: c_int = -28;
pub static LIBSSH2_ERROR_ZLIB: c_int = -29;
pub static LIBSSH2_ERROR_SOCKET_TIMEOUT: c_int = -30;
pub static LIBSSH2_ERROR_SFTP_PROTOCOL: c_int = -31;
pub static LIBSSH2_ERROR_REQUEST_DENIED: c_int = -32;
pub static LIBSSH2_ERROR_METHOD_NOT_SUPPORTED: c_int = -33;
pub static LIBSSH2_ERROR_INVAL: c_int = -34;
pub static LIBSSH2_ERROR_INVALID_POLL_TYPE: c_int = -35;
pub static LIBSSH2_ERROR_PUBLICKEY_PROTOCOL: c_int = -36;
pub static LIBSSH2_ERROR_EAGAIN: c_int = -37;
pub static LIBSSH2_ERROR_BUFFER_TOO_SMALL: c_int = -38;
pub static LIBSSH2_ERROR_BAD_USE: c_int = -39;
pub static LIBSSH2_ERROR_COMPRESS: c_int = -40;
pub static LIBSSH2_ERROR_OUT_OF_BOUNDARY: c_int = -41;
pub static LIBSSH2_ERROR_AGENT_PROTOCOL: c_int = -42;
pub static LIBSSH2_ERROR_SOCKET_RECV: c_int = -43;
pub static LIBSSH2_ERROR_ENCRYPT: c_int = -44;
pub static LIBSSH2_ERROR_BAD_SOCKET: c_int = -45;
pub static LIBSSH2_ERROR_KNOWN_HOSTS: c_int = -46;

pub enum LIBSSH2_SESSION {}
pub enum LIBSSH2_AGENT {}
pub enum LIBSSH2_CHANNEL {}
pub enum LIBSSH2_LISTENER {}

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
    pub fn libssh2_channel_read_ex(chan: *mut LIBSSH2_CHANNEL,
                                   stream_id: c_int,
                                   buf: *mut c_char,
                                   buflen: size_t) -> c_int;
    pub fn libssh2_channel_setenv_ex(chan: *mut LIBSSH2_CHANNEL,
                                     var: *const c_char,
                                     varlen: c_uint,
                                     val: *const c_char,
                                     vallen: c_uint) -> c_int;
    pub fn libssh2_channel_send_eof(chan: *mut LIBSSH2_CHANNEL) -> c_int;
    pub fn libssh2_channel_request_pty_ex(chan: *mut LIBSSH2_CHANNEL,
                                          term: *const c_char,
                                          termlen: c_uint,
                                          modes: *const c_char,
                                          modeslen: c_uint,
                                          width: c_int,
                                          height: c_int,
                                          width_px: c_int,
                                          height_px: c_int) -> c_int;
    pub fn libssh2_channel_request_pty_size_ex(chan: *mut LIBSSH2_CHANNEL,
                                               width: c_int,
                                               height: c_int,
                                               width_px: c_int,
                                               height_px: c_int) -> c_int;
    pub fn libssh2_channel_window_read_ex(chan: *mut LIBSSH2_CHANNEL,
                                          read_avail: *mut c_uint,
                                          window_size_initial: *mut c_uint)
                                          -> c_uint;
    pub fn libssh2_channel_window_write_ex(chan: *mut LIBSSH2_CHANNEL,
                                           window_size_initial: *mut c_uint)
                                           -> c_uint;
    pub fn libssh2_channel_receive_window_adjust2(chan: *mut LIBSSH2_CHANNEL,
                                                  adjust: c_uint,
                                                  force: c_uchar,
                                                  window: *mut c_uint) -> c_int;
    pub fn libssh2_channel_direct_tcpip_ex(ses: *mut LIBSSH2_SESSION,
                                           host: *const c_char,
                                           port: c_int,
                                           shost: *const c_char,
                                           sport: c_int)
                                           -> *mut LIBSSH2_CHANNEL;
    pub fn libssh2_channel_forward_accept(listener: *mut LIBSSH2_LISTENER)
                                          -> *mut LIBSSH2_CHANNEL;
    pub fn libssh2_channel_forward_cancel(listener: *mut LIBSSH2_LISTENER)
                                          -> c_int;
    pub fn libssh2_channel_forward_listen_ex(sess: *mut LIBSSH2_SESSION,
                                             host: *mut c_char,
                                             port: c_int,
                                             bound_port: *mut c_int,
                                             queue_maxsize: c_int)
                                             -> *mut LIBSSH2_LISTENER;

    // userauth
    pub fn libssh2_userauth_authenticated(sess: *mut LIBSSH2_SESSION) -> c_int;
    pub fn libssh2_userauth_list(sess: *mut LIBSSH2_SESSION,
                                 username: *const c_char,
                                 username_len: c_uint) -> *const c_char;
}
