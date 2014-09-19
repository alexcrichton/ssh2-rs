use std::io;
use std::kinds::marker;
use std::vec;
use libc::{c_uint, c_int, size_t, c_char, c_void, c_uchar};

use {raw, Session, Error};

pub struct Channel<'a> {
    raw: *mut raw::LIBSSH2_CHANNEL,
    sess: &'a Session,
    marker: marker::NoSync,
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
pub struct ReadWindow {
    /// The number of bytes which the remote end may send without overflowing
    /// the window limit.
    pub remaining: uint,
    /// The number of bytes actually available to be read.
    pub available: uint,
    /// The window_size_initial as defined by the channel open request
    pub window_size_initial: uint,
}

/// Description of the write window as returned by `Channel::write_window`
pub struct WriteWindow {
    /// The number of bytes which may be safely written on the channel without
    /// blocking.
    pub remaining: uint,
    /// The window_size_initial as defined by the channel open request
    pub window_size_initial: uint,
}

impl<'a> Channel<'a> {
    /// Wraps a raw pointer in a new Channel structure tied to the lifetime of the
    /// given session.
    ///
    /// This consumes ownership of `raw`.
    pub unsafe fn from_raw(sess: &Session,
                           raw: *mut raw::LIBSSH2_CHANNEL) -> Channel {
        Channel {
            raw: raw,
            sess: sess,
            marker: marker::NoSync,
        }
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
        unsafe {
            self.sess.rc(raw::libssh2_channel_close(self.raw))
        }
    }

    /// Enter a temporary blocking state until the remote host closes the named
    /// channel.
    ///
    /// Typically sent after `close` in order to examine the exit status.
    pub fn wait_close(&mut self) -> Result<(), Error> {
        unsafe { self.sess.rc(raw::libssh2_channel_wait_closed(self.raw)) }
    }

    /// Wait for the remote end to acknowledge an EOF request.
    pub fn wait_eof(&mut self) -> Result<(), Error> {
        unsafe { self.sess.rc(raw::libssh2_channel_wait_eof(self.raw)) }
    }

    /// Check if the remote host has sent an EOF status for the selected stream.
    pub fn eof(&self) -> bool {
        unsafe { raw::libssh2_channel_eof(self.raw) != 0 }
    }

    /// Initiate a request on a session type channel.
    ///
    /// The SSH2 protocol currently defines shell, exec, and subsystem as
    /// standard process services.
    pub fn process_startup(&mut self, request: &str, message: Option<&str>)
                           -> Result<(), Error> {
        let message_len = message.map(|s| s.len()).unwrap_or(0);
        let message = message.map(|s| s.as_ptr()).unwrap_or(0 as *const _);
        unsafe {
            let rc = raw::libssh2_channel_process_startup(self.raw,
                        request.as_ptr() as *const _, request.len() as c_uint,
                        message as *const _, message_len as c_uint);
            self.sess.rc(rc)
        }
    }

    /// Request a PTY on an established channel.
    ///
    /// Note that this does not make sense for all channel types and may be
    /// ignored by the server despite returning success.
    ///
    /// The dimensions argument is a tuple of (width, height, width_px,
    /// height_px)
    pub fn request_pty(&mut self, term: &str,
                       mode: Option<&str>,
                       dim: Option<(uint, uint, uint, uint)>)
                       -> Result<(), Error>{
        self.sess.rc(unsafe {
            let (width, height, width_px, height_px) =
                dim.unwrap_or((80, 24, 0, 0));
            raw::libssh2_channel_request_pty_ex(self.raw,
                                                term.as_ptr() as *const _,
                                                term.len() as c_uint,
                                                mode.map(|s| s.as_ptr())
                                                    .unwrap_or(0 as *const _)
                                                        as *const _,
                                                mode.map(|s| s.len())
                                                    .unwrap_or(0) as c_uint,
                                                width as c_int,
                                                height as c_int,
                                                width_px as c_int,
                                                height_px as c_int)
        })
    }

    /// Request a PTY of a specified size
    pub fn request_pty_size(&mut self, width: uint, height: uint,
                            width_px: Option<uint>, height_px: Option<uint>)
                            -> Result<(), Error> {
        let width_px = width_px.unwrap_or(0);
        let height_px = height_px.unwrap_or(0);
        self.sess.rc(unsafe {
            raw::libssh2_channel_request_pty_size_ex(self.raw,
                                                     width as c_int,
                                                     height as c_int,
                                                     width_px as c_int,
                                                     height_px as c_int)
        })
    }

    /// Execute a command
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use ssh2::Session;
    /// # let session: Session = fail!();
    /// let mut channel = session.channel_session().unwrap();
    /// channel.exec("ls").unwrap();
    /// println!("{}", channel.read_to_string().unwrap());
    /// ```
    pub fn exec(&mut self, command: &str) -> Result<(), Error> {
        self.process_startup("exec", Some(command))
    }

    /// Start a shell
    pub fn shell(&mut self) -> Result<(), Error> {
        self.process_startup("shell", None)
    }

    /// Request a subsystem be started
    pub fn subsystem(&mut self, system: &str) -> Result<(), Error> {
        self.process_startup("subsystem", Some(system))
    }

    /// Flush the read buffer for a given channel instance.
    ///
    /// Groups of substreams may be flushed by passing on of the following
    /// constants
    ///
    /// * FlushExtendedData - Flush all extended data substreams
    /// * FlushAll - Flush all substreams
    pub fn flush_stream(&mut self, stream_id: uint) -> Result<(), Error> {
        unsafe {
            self.sess.rc(raw::libssh2_channel_flush_ex(self.raw,
                                                       stream_id as c_int))
        }
    }

    /// Flush the stderr buffers.
    pub fn flush_stderr(&mut self) -> Result<(), Error> {
        self.flush_stream(::ExtendedDataStderr)
    }

    /// Write data to a channel stream.
    ///
    /// All channel streams have one standard I/O substream (stream_id == 0),
    /// and may have up to 2^32 extended data streams as identified by the
    /// selected stream_id. The SSH2 protocol currently defines a stream ID of 1
    /// to be the stderr substream.
    pub fn write_stream(&mut self, stream_id: uint, data: &[u8])
                        -> Result<(), Error> {
        unsafe {
            let rc = raw::libssh2_channel_write_ex(self.raw,
                                                   stream_id as c_int,
                                                   data.as_ptr() as *mut _,
                                                   data.len() as size_t);
            self.sess.rc(rc)
        }
    }

    /// Write data to the channel stderr stream.
    pub fn write_stderr(&mut self, data: &[u8]) -> Result<(), Error> {
        self.write_stream(::ExtendedDataStderr, data)
    }

    /// Get the remote exit signal.
    pub fn exit_signal(&self) -> Result<ExitSignal, Error> {
        unsafe {
            let mut sig = 0 as *mut _;
            let mut siglen = 0;
            let mut msg = 0 as *mut _;
            let mut msglen = 0;
            let mut lang = 0 as *mut _;
            let mut langlen = 0;
            let rc = raw::libssh2_channel_get_exit_signal(self.raw,
                                                          &mut sig, &mut siglen,
                                                          &mut msg, &mut msglen,
                                                          &mut lang,
                                                          &mut langlen);
            try!(self.sess.rc(rc));
            return Ok(ExitSignal {
                exit_signal: convert(self, sig, siglen),
                error_message: convert(self, msg, msglen),
                lang_tag: convert(self, lang, langlen),
            })
        }

        unsafe fn convert(chan: &Channel, ptr: *mut c_char,
                          len: size_t) -> Option<String> {
            if ptr.is_null() { return None }
            let ret = vec::raw::from_buf(ptr as *const u8, len as uint);
            raw::libssh2_free(chan.sess.raw(), ptr as *mut c_void);
            String::from_utf8(ret).ok()
        }
    }

    /// Returns the exit code raised by the process running on the remote host
    /// at the other end of the named channel.
    ///
    /// Note that the exit status may not be available if the remote end has not
    /// yet set its status to closed.
    pub fn exit_status(&self) -> Result<int, Error> {
        let ret = unsafe { raw::libssh2_channel_get_exit_status(self.raw) };
        match Error::last_error(self.sess) {
            Some(err) => Err(err),
            None => Ok(ret as int)
        }
    }

    /// Attempt to read data from an active channel stream.
    ///
    /// All channel streams have one standard I/O substream (stream_id == 0),
    /// and may have up to 2^32 extended data streams as identified by the
    /// selected stream_id. The SSH2 protocol currently defines a stream ID of 1
    /// to be the stderr substream.
    pub fn read_stream(&mut self, stream_id: uint, data: &mut [u8])
                       -> Result<uint, Error> {
        unsafe {
            let rc = raw::libssh2_channel_read_ex(self.raw,
                                                  stream_id as c_int,
                                                  data.as_mut_ptr() as *mut _,
                                                  data.len() as size_t);
            if rc < 0 { try!(self.sess.rc(rc)); }
            if rc == 0 && self.eof() { return Err(Error::eof()) }
            Ok(rc as uint)
        }
    }

    /// Read from the stderr stream .
    pub fn read_stderr(&mut self, data: &mut [u8]) -> Result<uint, Error> {
        self.read_stream(::ExtendedDataStderr, data)
    }

    /// Set an environment variable in the remote channel's process space.
    ///
    /// Note that this does not make sense for all channel types and may be
    /// ignored by the server despite returning success.
    pub fn setenv(&mut self, var: &str, val: &str) -> Result<(), Error> {
        unsafe {
            self.sess.rc(raw::libssh2_channel_setenv_ex(self.raw,
                                                        var.as_ptr() as *const _,
                                                        var.len() as c_uint,
                                                        val.as_ptr() as *const _,
                                                        val.len() as c_uint))
        }
    }

    /// Tell the remote host that no further data will be sent on the specified
    /// channel.
    ///
    /// Processes typically interpret this as a closed stdin descriptor.
    pub fn send_eof(&mut self) -> Result<(), Error> {
        unsafe {
            self.sess.rc(raw::libssh2_channel_send_eof(self.raw))
        }
    }

    /// Check the status of the read window.
    pub fn read_window(&self) -> ReadWindow {
        unsafe {
            let mut avail = 0;
            let mut init = 0;
            let remaining = raw::libssh2_channel_window_read_ex(self.raw,
                                                                &mut avail,
                                                                &mut init);
            ReadWindow {
                remaining: remaining as uint,
                available: avail as uint,
                window_size_initial: init as uint,
            }
        }
    }

    /// Check the status of the write window.
    pub fn write_window(&self) -> WriteWindow {
        unsafe {
            let mut init = 0;
            let remaining = raw::libssh2_channel_window_write_ex(self.raw,
                                                                 &mut init);
            WriteWindow {
                remaining: remaining as uint,
                window_size_initial: init as uint,
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
    pub fn adjust_receive_window(&mut self, adjust: uint, force: bool)
                                 -> Result<uint, Error> {
        let mut ret = 0;
        let rc = unsafe {
            raw::libssh2_channel_receive_window_adjust2(self.raw,
                                                        adjust as c_uint,
                                                        force as c_uchar,
                                                        &mut ret)
        };
        try!(self.sess.rc(rc));
        Ok(ret as uint)
    }
}

impl<'a> Writer for Channel<'a> {
    fn write(&mut self, buf: &[u8]) -> io::IoResult<()> {
        self.write_stream(0, buf).map_err(|e| {
            io::IoError {
                kind: io::OtherIoError,
                desc: "ssh write error",
                detail: Some(e.to_string()),
            }
        })
    }

    fn flush(&mut self) -> io::IoResult<()> {
        self.flush_stream(0).map_err(|e| {
            io::IoError {
                kind: io::OtherIoError,
                desc: "ssh write error",
                detail: Some(e.to_string()),
            }
        })
    }
}

impl<'a> Reader for Channel<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::IoResult<uint> {
        self.read_stream(0, buf).map_err(|e| {
            if self.eof() {
                io::standard_error(io::EndOfFile)
            } else {
                io::IoError {
                    kind: io::OtherIoError,
                    desc: "ssh read error",
                    detail: Some(e.to_string()),
                }
            }
        })
    }
}

#[unsafe_destructor]
impl<'a> Drop for Channel<'a> {
    fn drop(&mut self) {
        unsafe { assert_eq!(raw::libssh2_channel_free(self.raw), 0) }
    }
}
