use std::io;
use std::kinds::marker;
use std::vec;
use libc::{c_uint, c_int, size_t, c_char, c_void};

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
        unsafe { self.sess.rc(raw::libssh2_channel_wait_close(self.raw)) }
    }

    /// Check if the remote host has sent an EOF status for the selected stream.
    pub fn eof(&self) -> bool {
        unsafe { raw::libssh2_channel_eof(self.raw) != 0 }
    }

    /// Initiate a request on a session type channel.
    ///
    /// The SSH2 protocol currently defines shell, exec, and subsystem as
    /// standard process services.
    pub fn process_startup(&mut self, request: &str, message: &str)
                           -> Result<(), Error> {
        unsafe {
            let rc = raw::libssh2_channel_process_startup(self.raw,
                        request.as_ptr() as *const _, request.len() as c_uint,
                        message.as_ptr() as *const _, message.len() as c_uint);
            self.sess.rc(rc)
        }
    }

    /// Execute a command
    pub fn exec(&mut self, command: &str) -> Result<(), Error> {
        self.process_startup("exec", command)
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
    pub fn get_exit_signal(&self) -> Result<ExitSignal, Error> {
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
    pub fn get_exit_status(&self) -> Result<int, Error> {
        let ret = unsafe { raw::libssh2_channel_get_exit_status(self.raw) };
        if ret == 0 {
            Err(Error::last_error(self.sess).unwrap())
        } else {
            Ok(ret as int)
        }
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

#[unsafe_destructor]
impl<'a> Drop for Channel<'a> {
    fn drop(&mut self) {
        unsafe { assert_eq!(raw::libssh2_channel_free(self.raw), 0) }
    }
}
