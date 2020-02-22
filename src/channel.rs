use libc::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void, size_t};
use parking_lot::{Mutex, MutexGuard};
use std::cmp;
use std::io;
use std::io::prelude::*;
use std::slice;
use std::sync::Arc;

use {raw, Error, ExtendedData, PtyModes, SessionInner};

struct ChannelInner {
    unsafe_raw: *mut raw::LIBSSH2_CHANNEL,
    sess: Arc<Mutex<SessionInner>>,
    read_limit: Mutex<Option<u64>>,
}

// ChannelInner is both Send and Sync; the compiler can't see it because it
// is pessimistic about the raw pointer.  We use Arc/Mutex to guard accessing
// the raw pointer so we are safe for both.
unsafe impl Send for ChannelInner {}
unsafe impl Sync for ChannelInner {}

struct LockedChannel<'a> {
    raw: *mut raw::LIBSSH2_CHANNEL,
    sess: MutexGuard<'a, SessionInner>,
}

/// A channel represents a portion of an SSH connection on which data can be
/// read and written.
///
/// Channels denote all of SCP uploads and downloads, shell sessions, remote
/// process executions, and other general-purpose sessions. Each channel
/// implements the `Reader` and `Writer` traits to send and receive data.
/// Whether or not I/O operations are blocking is mandated by the `blocking`
/// flag on a channel's corresponding `Session`.
pub struct Channel {
    channel_inner: Arc<ChannelInner>,
}

impl Channel {
    pub(crate) fn from_raw_opt(
        raw: *mut raw::LIBSSH2_CHANNEL,
        err: Option<Error>,
        sess: &Arc<Mutex<SessionInner>>,
    ) -> Result<Self, Error> {
        if raw.is_null() {
            Err(err.unwrap_or_else(Error::unknown))
        } else {
            Ok(Self {
                channel_inner: Arc::new(ChannelInner {
                    unsafe_raw: raw,
                    sess: Arc::clone(sess),
                    read_limit: Mutex::new(None),
                }),
            })
        }
    }

    fn lock(&self) -> LockedChannel {
        let sess = self.channel_inner.sess.lock();
        LockedChannel {
            sess,
            raw: self.channel_inner.unsafe_raw,
        }
    }
}

/// A channel can have a number of streams, each identified by an id, each of
/// which implements the `Read` and `Write` traits.
pub struct Stream {
    channel_inner: Arc<ChannelInner>,
    id: i32,
}

struct LockedStream<'a> {
    raw: *mut raw::LIBSSH2_CHANNEL,
    sess: MutexGuard<'a, SessionInner>,
    id: i32,
    read_limit: MutexGuard<'a, Option<u64>>,
}

impl<'a> LockedStream<'a> {
    pub fn eof(&self) -> bool {
        *self.read_limit == Some(0) || unsafe { raw::libssh2_channel_eof(self.raw) != 0 }
    }
}

/// Data received from when a program exits with a signal.
pub struct ExitSignal {
    /// The exit signal received, if the program did not exit cleanly. Does not
    /// contain a SIG prefix
    pub exit_signal: Option<String>,
    /// Error message provided by the remote server (if any)
    pub error_message: Option<String>,
    /// Language tag provided by the remote server (if any)
    pub lang_tag: Option<String>,
}

/// Description of the read window as returned by `Channel::read_window`
#[derive(Copy, Clone)]
pub struct ReadWindow {
    /// The number of bytes which the remote end may send without overflowing
    /// the window limit.
    pub remaining: u32,
    /// The number of bytes actually available to be read.
    pub available: u32,
    /// The window_size_initial as defined by the channel open request
    pub window_size_initial: u32,
}

/// Description of the write window as returned by `Channel::write_window`
#[derive(Copy, Clone)]
pub struct WriteWindow {
    /// The number of bytes which may be safely written on the channel without
    /// blocking.
    pub remaining: u32,
    /// The window_size_initial as defined by the channel open request
    pub window_size_initial: u32,
}

impl Channel {
    /// Set an environment variable in the remote channel's process space.
    ///
    /// Note that this does not make sense for all channel types and may be
    /// ignored by the server despite returning success.
    pub fn setenv(&mut self, var: &str, val: &str) -> Result<(), Error> {
        let locked = self.lock();
        unsafe {
            locked.sess.rc(raw::libssh2_channel_setenv_ex(
                locked.raw,
                var.as_ptr() as *const _,
                var.len() as c_uint,
                val.as_ptr() as *const _,
                val.len() as c_uint,
            ))
        }
    }

    /// Request a PTY on an established channel.
    ///
    /// Note that this does not make sense for all channel types and may be
    /// ignored by the server despite returning success.
    ///
    /// The dimensions argument is a tuple of (width, height, width_px,
    /// height_px)
    ///
    /// The mode parameter is optional and specifies modes to apply to
    /// the pty.  Use the `PtyModes` type construct these modes.
    /// A contrived example of this is below:
    ///
    /// ```
    /// let mut mode = ssh2::PtyModes::new();
    /// // Set the interrupt character to CTRL-C (ASCII 3: ETX).
    /// // This is typically the default, but we're showing how to
    /// // set a relatable option for the sake of example!
    /// mode.set_character(ssh2::PtyModeOpcode::VINTR, Some(3 as char));
    /// ```
    pub fn request_pty(
        &mut self,
        term: &str,
        mode: Option<PtyModes>,
        dim: Option<(u32, u32, u32, u32)>,
    ) -> Result<(), Error> {
        let locked = self.lock();
        let mode = mode.map(PtyModes::finish);
        let mode = mode.as_ref().map(Vec::as_slice).unwrap_or(&[]);
        locked.sess.rc(unsafe {
            let (width, height, width_px, height_px) = dim.unwrap_or((80, 24, 0, 0));
            raw::libssh2_channel_request_pty_ex(
                locked.raw,
                term.as_ptr() as *const _,
                term.len() as c_uint,
                mode.as_ptr() as *const _,
                mode.len() as c_uint,
                width as c_int,
                height as c_int,
                width_px as c_int,
                height_px as c_int,
            )
        })
    }

    /// Request that the PTY size be changed to the specified size.
    /// width and height are the number of character cells, and you
    /// may optionally include the size specified in pixels.
    pub fn request_pty_size(
        &mut self,
        width: u32,
        height: u32,
        width_px: Option<u32>,
        height_px: Option<u32>,
    ) -> Result<(), Error> {
        let locked = self.lock();
        let width_px = width_px.unwrap_or(0);
        let height_px = height_px.unwrap_or(0);
        locked.sess.rc(unsafe {
            raw::libssh2_channel_request_pty_size_ex(
                locked.raw,
                width as c_int,
                height as c_int,
                width_px as c_int,
                height_px as c_int,
            )
        })
    }

    /// Requests that the remote host start an authentication agent;
    /// if successful requests to that agent will be forwarded from
    /// the server back to the local authentication agent on the client side.
    ///
    /// Note that some hosts are configured to disallow agent forwarding,
    /// and that even if enabled, there is a possibility that starting
    /// the agent on the remote system can fail.
    pub fn request_auth_agent_forwarding(&mut self) -> Result<(), Error> {
        let locked = self.lock();
        locked
            .sess
            .rc(unsafe { raw::libssh2_channel_request_auth_agent(locked.raw) })
    }

    /// Execute a command
    ///
    /// An execution is one of the standard process services defined by the SSH2
    /// protocol.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::io::prelude::*;
    /// # use ssh2::Session;
    /// # let session: Session = panic!();
    /// let mut channel = session.channel_session().unwrap();
    /// channel.exec("ls").unwrap();
    /// let mut s = String::new();
    /// channel.read_to_string(&mut s).unwrap();
    /// println!("{}", s);
    /// ```
    pub fn exec(&mut self, command: &str) -> Result<(), Error> {
        self.process_startup("exec", Some(command))
    }

    /// Start a shell
    ///
    /// A shell is one of the standard process services defined by the SSH2
    /// protocol.
    pub fn shell(&mut self) -> Result<(), Error> {
        self.process_startup("shell", None)
    }

    /// Request a subsystem be started.
    ///
    /// A subsystem is one of the standard process services defined by the SSH2
    /// protocol.
    pub fn subsystem(&mut self, system: &str) -> Result<(), Error> {
        self.process_startup("subsystem", Some(system))
    }

    /// Initiate a request on a session type channel.
    ///
    /// The SSH2 protocol currently defines shell, exec, and subsystem as
    /// standard process services.
    pub fn process_startup(&mut self, request: &str, message: Option<&str>) -> Result<(), Error> {
        let message_len = message.map(|s| s.len()).unwrap_or(0);
        let message = message.map(|s| s.as_ptr()).unwrap_or(0 as *const _);
        let locked = self.lock();
        unsafe {
            let rc = raw::libssh2_channel_process_startup(
                locked.raw,
                request.as_ptr() as *const _,
                request.len() as c_uint,
                message as *const _,
                message_len as c_uint,
            );
            locked.sess.rc(rc)
        }
    }

    /// Get a handle to the stderr stream of this channel.
    ///
    /// The returned handle implements the `Read` and `Write` traits.
    pub fn stderr(&self) -> Stream {
        self.stream(::EXTENDED_DATA_STDERR)
    }

    /// Get a handle to a particular stream for this channel.
    ///
    /// The returned handle implements the `Read` and `Write` traits.
    ///
    /// Groups of substreams may be flushed by passing on of the following
    /// constants and then calling `flush()`.
    ///
    /// * FLUSH_EXTENDED_DATA - Flush all extended data substreams
    /// * FLUSH_ALL - Flush all substreams
    pub fn stream(&self, stream_id: i32) -> Stream {
        Stream {
            channel_inner: Arc::clone(&self.channel_inner),
            id: stream_id,
        }
    }

    /// Change how extended data (such as stderr) is handled
    pub fn handle_extended_data(&mut self, mode: ExtendedData) -> Result<(), Error> {
        let locked = self.lock();
        unsafe {
            let rc = raw::libssh2_channel_handle_extended_data2(locked.raw, mode as c_int);
            locked.sess.rc(rc)
        }
    }

    /// Returns the exit code raised by the process running on the remote host
    /// at the other end of the named channel.
    ///
    /// Note that the exit status may not be available if the remote end has not
    /// yet set its status to closed.
    pub fn exit_status(&self) -> Result<i32, Error> {
        let locked = self.lock();
        // Should really store existing error, call function, check for error
        // after and restore previous error if no new one...but the only error
        // condition right now is a NULL pointer check on self.raw, so let's
        // assume that's not the case.
        Ok(unsafe { raw::libssh2_channel_get_exit_status(locked.raw) })
    }

    /// Get the remote exit signal.
    pub fn exit_signal(&self) -> Result<ExitSignal, Error> {
        let locked = self.lock();
        unsafe {
            let mut sig = 0 as *mut _;
            let mut siglen = 0;
            let mut msg = 0 as *mut _;
            let mut msglen = 0;
            let mut lang = 0 as *mut _;
            let mut langlen = 0;
            let rc = raw::libssh2_channel_get_exit_signal(
                locked.raw,
                &mut sig,
                &mut siglen,
                &mut msg,
                &mut msglen,
                &mut lang,
                &mut langlen,
            );
            locked.sess.rc(rc)?;
            return Ok(ExitSignal {
                exit_signal: convert(&locked, sig, siglen),
                error_message: convert(&locked, msg, msglen),
                lang_tag: convert(&locked, lang, langlen),
            });
        }

        unsafe fn convert(locked: &LockedChannel, ptr: *mut c_char, len: size_t) -> Option<String> {
            if ptr.is_null() {
                return None;
            }
            let slice = slice::from_raw_parts(ptr as *const u8, len as usize);
            let ret = slice.to_vec();
            raw::libssh2_free(locked.sess.raw, ptr as *mut c_void);
            String::from_utf8(ret).ok()
        }
    }

    /// Check the status of the read window.
    pub fn read_window(&self) -> ReadWindow {
        let locked = self.lock();
        unsafe {
            let mut avail = 0;
            let mut init = 0;
            let remaining = raw::libssh2_channel_window_read_ex(locked.raw, &mut avail, &mut init);
            ReadWindow {
                remaining: remaining as u32,
                available: avail as u32,
                window_size_initial: init as u32,
            }
        }
    }

    /// Check the status of the write window.
    pub fn write_window(&self) -> WriteWindow {
        let locked = self.lock();
        unsafe {
            let mut init = 0;
            let remaining = raw::libssh2_channel_window_write_ex(locked.raw, &mut init);
            WriteWindow {
                remaining: remaining as u32,
                window_size_initial: init as u32,
            }
        }
    }

    /// Adjust the receive window for a channel by adjustment bytes.
    ///
    /// If the amount to be adjusted is less than the minimum adjustment and
    /// force is false, the adjustment amount will be queued for a later packet.
    ///
    /// This function returns the new size of the receive window (as understood
    /// by remote end) on success.
    pub fn adjust_receive_window(&mut self, adjust: u64, force: bool) -> Result<u64, Error> {
        let locked = self.lock();
        let mut ret = 0;
        let rc = unsafe {
            raw::libssh2_channel_receive_window_adjust2(
                locked.raw,
                adjust as c_ulong,
                force as c_uchar,
                &mut ret,
            )
        };
        locked.sess.rc(rc)?;
        Ok(ret as u64)
    }

    /// Artificially limit the number of bytes that will be read from this
    /// channel. Hack intended for use by scp_recv only.
    #[doc(hidden)]
    pub(crate) fn limit_read(&mut self, limit: u64) {
        *self.channel_inner.read_limit.lock() = Some(limit);
    }

    /// Check if the remote host has sent an EOF status for the channel.
    /// Take care: the EOF status is for the entire channel which can be confusing
    /// because the reading from the channel reads only the stdout stream.
    /// unread, buffered, stderr data will cause eof() to return false.
    pub fn eof(&self) -> bool {
        let locked = self.lock();
        *self.channel_inner.read_limit.lock() == Some(0)
            || unsafe { raw::libssh2_channel_eof(locked.raw) != 0 }
    }

    /// Tell the remote host that no further data will be sent on the specified
    /// channel.
    ///
    /// Processes typically interpret this as a closed stdin descriptor.
    pub fn send_eof(&mut self) -> Result<(), Error> {
        let locked = self.lock();
        unsafe { locked.sess.rc(raw::libssh2_channel_send_eof(locked.raw)) }
    }

    /// Wait for the remote end to send EOF.
    /// Note that unread buffered stdout and stderr will cause this function
    /// to return `Ok(())` without waiting.
    /// You should call the eof() function after calling this to check the
    /// status of the channel.
    pub fn wait_eof(&mut self) -> Result<(), Error> {
        let locked = self.lock();
        unsafe { locked.sess.rc(raw::libssh2_channel_wait_eof(locked.raw)) }
    }

    /// Close an active data channel.
    ///
    /// In practice this means sending an SSH_MSG_CLOSE packet to the remote
    /// host which serves as instruction that no further data will be sent to
    /// it. The remote host may still send data back until it sends its own
    /// close message in response.
    ///
    /// To wait for the remote end to close its connection as well, follow this
    /// command with `wait_closed`
    pub fn close(&mut self) -> Result<(), Error> {
        let locked = self.lock();
        unsafe { locked.sess.rc(raw::libssh2_channel_close(locked.raw)) }
    }

    /// Enter a temporary blocking state until the remote host closes the named
    /// channel.
    ///
    /// Typically sent after `close` in order to examine the exit status.
    pub fn wait_close(&mut self) -> Result<(), Error> {
        let locked = self.lock();
        unsafe { locked.sess.rc(raw::libssh2_channel_wait_closed(locked.raw)) }
    }
}

impl Write for Channel {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream(0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream(0).flush()
    }
}

impl Read for Channel {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream(0).read(buf)
    }
}

impl Drop for ChannelInner {
    fn drop(&mut self) {
        unsafe {
            let _ = raw::libssh2_channel_free(self.unsafe_raw);
        }
    }
}

impl Stream {
    fn lock(&self) -> LockedStream {
        let sess = self.channel_inner.sess.lock();
        LockedStream {
            sess,
            raw: self.channel_inner.unsafe_raw,
            id: self.id,
            read_limit: self.channel_inner.read_limit.lock(),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let mut locked = self.lock();
        if locked.eof() {
            return Ok(0);
        }

        let data = match locked.read_limit.as_mut() {
            Some(amt) => {
                let len = data.len();
                &mut data[..cmp::min(*amt as usize, len)]
            }
            None => data,
        };
        let ret = unsafe {
            let rc = raw::libssh2_channel_read_ex(
                locked.raw,
                locked.id as c_int,
                data.as_mut_ptr() as *mut _,
                data.len() as size_t,
            );
            locked.sess.rc(rc as c_int).map(|()| rc as usize)
        };
        match ret {
            Ok(n) => {
                if let Some(ref mut amt) = locked.read_limit.as_mut() {
                    **amt -= n as u64;
                }
                Ok(n)
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let locked = self.lock();
        unsafe {
            let rc = raw::libssh2_channel_write_ex(
                locked.raw,
                locked.id as c_int,
                data.as_ptr() as *mut _,
                data.len() as size_t,
            );
            locked.sess.rc(rc as c_int).map(|()| rc as usize)
        }
        .map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        let locked = self.lock();
        unsafe {
            let rc = raw::libssh2_channel_flush_ex(locked.raw, locked.id as c_int);
            locked.sess.rc(rc)
        }
        .map_err(Into::into)
    }
}
