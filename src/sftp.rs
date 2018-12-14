use std::io::prelude::*;
use std::io::{self, ErrorKind, SeekFrom};
use std::marker;
use std::mem;
use std::path::{Path, PathBuf};
use libc::{c_int, c_ulong, c_long, c_uint, size_t};

use {raw, Session, Error, Channel};
use util::{self, SessionBinding};

/// A handle to a remote filesystem over SFTP.
///
/// Instances are created through the `sftp` method on a `Session`.
pub struct Sftp<'sess> {
    raw: *mut raw::LIBSSH2_SFTP,
    _marker: marker::PhantomData<Channel<'sess>>,
}

/// A file handle to an SFTP connection.
///
/// Files behave similarly to `std::old_io::File` in that they are readable and
/// writable and support operations like stat and seek.
///
/// Files are created through `open`, `create`, and `open_mode` on an instance
/// of `Sftp`.
pub struct File<'sftp> {
    raw: *mut raw::LIBSSH2_SFTP_HANDLE,
    sftp: &'sftp Sftp<'sftp>,
}

/// Metadata information about a remote file.
///
/// Fields are not necessarily all provided
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_copy_implementations)]
pub struct FileStat {
    /// File size, in bytes of the file.
    pub size: Option<u64>,
    /// Owner ID of the file
    pub uid: Option<u32>,
    /// Owning group of the file
    pub gid: Option<u32>,
    /// Permissions (mode) of the file
    pub perm: Option<u32>,
    /// Last access time of the file
    pub atime: Option<u64>,
    /// Last modification time of the file
    pub mtime: Option<u64>,
}

/// An structure representing a type of file.
pub struct FileType {
    perm: c_ulong,
}

bitflags! {
    /// Options that can be used to configure how a file is opened
    pub struct OpenFlags: c_ulong {
        /// Open the file for reading.
        const READ = raw::LIBSSH2_FXF_READ;
        /// Open the file for writing. If both this and `Read` are specified,
        /// the file is opened for both reading and writing.
        const WRITE = raw::LIBSSH2_FXF_WRITE;
        /// Force all writes to append data at the end of the file.
        const APPEND = raw::LIBSSH2_FXF_APPEND;
        /// If this flag is specified, then a new file will be created if one
        /// does not already exist (if `Truncate` is specified, the new file
        /// will be truncated to zero length if it previously exists).
        const CREATE = raw::LIBSSH2_FXF_CREAT;
        /// Forces an existing file with the same name to be truncated to zero
        /// length when creating a file by specifying `Create`. Using this flag
        /// implies the `Create` flag.
        const TRUNCATE = raw::LIBSSH2_FXF_TRUNC | Self::CREATE.bits;
        /// Causes the request to fail if the named file already exists. Using
        /// this flag implies the `Create` flag.
        const EXCLUSIVE = raw::LIBSSH2_FXF_EXCL | Self::CREATE.bits;
    }
}

bitflags! {
    /// Options to `Sftp::rename`.
    pub struct RenameFlags: c_long {
        /// In a rename operation, overwrite the destination if it already
        /// exists. If this flag is not present then it is an error if the
        /// destination already exists.
        const OVERWRITE = raw::LIBSSH2_SFTP_RENAME_OVERWRITE;
        /// Inform the remote that an atomic rename operation is desired if
        /// available.
        const ATOMIC = raw::LIBSSH2_SFTP_RENAME_ATOMIC;
        /// Inform the remote end that the native system calls for renaming
        /// should be used.
        const NATIVE = raw::LIBSSH2_SFTP_RENAME_NATIVE;
    }
}

/// How to open a file handle with libssh2.
#[derive(Copy, Clone)]
pub enum OpenType {
    /// Specify that a file shoud be opened.
    File = raw::LIBSSH2_SFTP_OPENFILE as isize,
    /// Specify that a directory should be opened.
    Dir = raw::LIBSSH2_SFTP_OPENDIR as isize,
}

impl<'sess> Sftp<'sess> {
    /// Open a handle to a file.
    pub fn open_mode(&self, filename: &Path, flags: OpenFlags,
                     mode: i32, open_type: OpenType) -> Result<File, Error> {
        let filename = try!(util::path2bytes(filename));
        unsafe {
            let ret = raw::libssh2_sftp_open_ex(self.raw,
                                                filename.as_ptr() as *const _,
                                                filename.len() as c_uint,
                                                flags.bits() as c_ulong,
                                                mode as c_long,
                                                open_type as c_int);
            if ret.is_null() {
                Err(self.last_error())
            } else {
                Ok(File::from_raw(self, ret))
            }
        }
    }

    /// Helper to open a file in the `Read` mode.
    pub fn open(&self, filename: &Path) -> Result<File, Error> {
        self.open_mode(filename, OpenFlags::READ, 0o644, OpenType::File)
    }

    /// Helper to create a file in write-only mode with truncation.
    pub fn create(&self, filename: &Path) -> Result<File, Error> {
        self.open_mode(filename, OpenFlags::WRITE | OpenFlags::TRUNCATE, 0o644, OpenType::File)
    }

    /// Helper to open a directory for reading its contents.
    pub fn opendir(&self, dirname: &Path) -> Result<File, Error> {
        self.open_mode(dirname, OpenFlags::READ, 0, OpenType::Dir)
    }

    /// Convenience function to read the files in a directory.
    ///
    /// The returned paths are all joined with `dirname` when returned, and the
    /// paths `.` and `..` are filtered out of the returned list.
    pub fn readdir(&self, dirname: &Path)
                   -> Result<Vec<(PathBuf, FileStat)>, Error> {
        let mut dir = try!(self.opendir(dirname));
        let mut ret = Vec::new();
        loop {
            match dir.readdir() {
                Ok((filename, stat)) => {
                    if &*filename == Path::new(".") ||
                       &*filename == Path::new("..") { continue }

                    ret.push((dirname.join(&filename), stat))
                }
                Err(ref e) if e.code() == raw::LIBSSH2_ERROR_FILE => break,
                Err(e) => return Err(e),
            }
        }
        Ok(ret)
    }

    /// Create a directory on the remote file system.
    pub fn mkdir(&self, filename: &Path, mode: i32)
                 -> Result<(), Error> {
        let filename = try!(util::path2bytes(filename));
        self.rc(unsafe {
            raw::libssh2_sftp_mkdir_ex(self.raw,
                                       filename.as_ptr() as *const _,
                                       filename.len() as c_uint,
                                       mode as c_long)
        })
    }

    /// Remove a directory from the remote file system.
    pub fn rmdir(&self, filename: &Path) -> Result<(), Error> {
        let filename = try!(util::path2bytes(filename));
        self.rc(unsafe {
            raw::libssh2_sftp_rmdir_ex(self.raw,
                                       filename.as_ptr() as *const _,
                                       filename.len() as c_uint)
        })
    }

    /// Get the metadata for a file, performed by stat(2)
    pub fn stat(&self, filename: &Path) -> Result<FileStat, Error> {
        let filename = try!(util::path2bytes(filename));
        unsafe {
            let mut ret = mem::zeroed();
            let rc = raw::libssh2_sftp_stat_ex(self.raw,
                                               filename.as_ptr() as *const _,
                                               filename.len() as c_uint,
                                               raw::LIBSSH2_SFTP_STAT,
                                               &mut ret);
            try!(self.rc(rc));
            Ok(FileStat::from_raw(&ret))
        }
    }

    /// Get the metadata for a file, performed by lstat(2)
    pub fn lstat(&self, filename: &Path) -> Result<FileStat, Error> {
        let filename = try!(util::path2bytes(filename));
        unsafe {
            let mut ret = mem::zeroed();
            let rc = raw::libssh2_sftp_stat_ex(self.raw,
                                               filename.as_ptr() as *const _,
                                               filename.len() as c_uint,
                                               raw::LIBSSH2_SFTP_LSTAT,
                                               &mut ret);
            try!(self.rc(rc));
            Ok(FileStat::from_raw(&ret))
        }
    }

    /// Set the metadata for a file.
    pub fn setstat(&self, filename: &Path, stat: FileStat) -> Result<(), Error> {
        let filename = try!(util::path2bytes(filename));
        self.rc(unsafe {
            let mut raw = stat.raw();
            raw::libssh2_sftp_stat_ex(self.raw,
                                      filename.as_ptr() as *const _,
                                      filename.len() as c_uint,
                                      raw::LIBSSH2_SFTP_SETSTAT,
                                      &mut raw)
        })
    }

    /// Create a symlink at `target` pointing at `path`.
    pub fn symlink(&self, path: &Path, target: &Path) -> Result<(), Error> {
        let path = try!(util::path2bytes(path));
        let target = try!(util::path2bytes(target));
        self.rc(unsafe {
            raw::libssh2_sftp_symlink_ex(self.raw,
                                         path.as_ptr() as *const _,
                                         path.len() as c_uint,
                                         target.as_ptr() as *mut _,
                                         target.len() as c_uint,
                                         raw::LIBSSH2_SFTP_SYMLINK)
        })
    }

    /// Read a symlink at `path`.
    pub fn readlink(&self, path: &Path) -> Result<PathBuf, Error> {
        self.readlink_op(path, raw::LIBSSH2_SFTP_READLINK)
    }

    /// Resolve the real path for `path`.
    pub fn realpath(&self, path: &Path) -> Result<PathBuf, Error> {
        self.readlink_op(path, raw::LIBSSH2_SFTP_REALPATH)
    }

    fn readlink_op(&self, path: &Path, op: c_int) -> Result<PathBuf, Error> {
        let path = try!(util::path2bytes(path));
        let mut ret = Vec::<u8>::with_capacity(128);
        let mut rc;
        loop {
            rc = unsafe {
                raw::libssh2_sftp_symlink_ex(self.raw,
                                             path.as_ptr() as *const _,
                                             path.len() as c_uint,
                                             ret.as_ptr() as *mut _,
                                             ret.capacity() as c_uint,
                                             op)
            };
            if rc == raw::LIBSSH2_ERROR_BUFFER_TOO_SMALL {
                let cap = ret.capacity();
                ret.reserve(cap);
            } else {
                break
            }
        }
        if rc < 0 {
            Err(self.last_error())
        } else {
            unsafe { ret.set_len(rc as usize) }
            Ok(mkpath(ret))
        }
    }

    /// Rename a filesystem object on the remote filesystem.
    ///
    /// The semantics of this command typically include the ability to move a
    /// filesystem object between folders and/or filesystem mounts. If the
    /// `Overwrite` flag is not set and the destfile entry already exists, the
    /// operation will fail.
    ///
    /// Use of the other flags (Native or Atomic) indicate a preference (but
    /// not a requirement) for the remote end to perform an atomic rename
    /// operation and/or using native system calls when possible.
    ///
    /// If no flags are specified then all flags are used.
    pub fn rename(&self, src: &Path, dst: &Path, flags: Option<RenameFlags>)
                  -> Result<(), Error> {
        let flags = flags.unwrap_or(
            RenameFlags::ATOMIC | RenameFlags::OVERWRITE | RenameFlags::NATIVE
        );
        let src = try!(util::path2bytes(src));
        let dst = try!(util::path2bytes(dst));
        self.rc(unsafe {
            raw::libssh2_sftp_rename_ex(self.raw,
                                        src.as_ptr() as *const _,
                                        src.len() as c_uint,
                                        dst.as_ptr() as *const _,
                                        dst.len() as c_uint,
                                        flags.bits())
        })
    }

    /// Remove a file on the remote filesystem
    pub fn unlink(&self, file: &Path) -> Result<(), Error> {
        let file = try!(util::path2bytes(file));
        self.rc(unsafe {
            raw::libssh2_sftp_unlink_ex(self.raw,
                                        file.as_ptr() as *const _,
                                        file.len() as c_uint)
        })
    }

    /// Peel off the last error to happen on this SFTP instance.
    pub fn last_error(&self) -> Error {
        let code = unsafe { raw::libssh2_sftp_last_error(self.raw) };
        Error::from_errno(code as c_int)
    }

    /// Translates a return code into a Rust-`Result`
    pub fn rc(&self, rc: c_int) -> Result<(), Error> {
        if rc == 0 {Ok(())} else {Err(self.last_error())}
    }
}

impl<'sess> SessionBinding<'sess> for Sftp<'sess> {
    type Raw = raw::LIBSSH2_SFTP;

    unsafe fn from_raw(_sess: &'sess Session,
                       raw: *mut raw::LIBSSH2_SFTP) -> Sftp<'sess> {
        Sftp { raw: raw, _marker: marker::PhantomData }
    }
    fn raw(&self) -> *mut raw::LIBSSH2_SFTP { self.raw }
}


impl<'sess> Drop for Sftp<'sess> {
    fn drop(&mut self) {
        unsafe { assert_eq!(raw::libssh2_sftp_shutdown(self.raw), 0) }
    }
}

impl<'sftp> File<'sftp> {
    /// Wraps a raw pointer in a new File structure tied to the lifetime of the
    /// given session.
    ///
    /// This consumes ownership of `raw`.
    unsafe fn from_raw(sftp: &'sftp Sftp<'sftp>,
                       raw: *mut raw::LIBSSH2_SFTP_HANDLE) -> File<'sftp> {
        File {
            raw: raw,
            sftp: sftp,
        }
    }

    /// Set the metadata for this handle.
    pub fn setstat(&mut self, stat: FileStat) -> Result<(), Error> {
        self.sftp.rc(unsafe {
            let mut raw = stat.raw();
            raw::libssh2_sftp_fstat_ex(self.raw, &mut raw, 1)
        })
    }

    /// Get the metadata for this handle.
    pub fn stat(&mut self) -> Result<FileStat, Error> {
        unsafe {
            let mut ret = mem::zeroed();
            try!(self.sftp.rc(raw::libssh2_sftp_fstat_ex(self.raw, &mut ret, 0)));
            Ok(FileStat::from_raw(&ret))
        }
    }

    #[allow(missing_docs)] // sure wish I knew what this did...
    pub fn statvfs(&mut self) -> Result<raw::LIBSSH2_SFTP_STATVFS, Error> {
        unsafe {
            let mut ret = mem::zeroed();
            try!(self.sftp.rc(raw::libssh2_sftp_fstatvfs(self.raw, &mut ret)));
            Ok(ret)
        }
    }

    /// Reads a block of data from a handle and returns file entry information
    /// for the next entry, if any.
    ///
    /// Note that this provides raw access to the `readdir` function from
    /// libssh2. This will return an error when there are no more files to
    /// read, and files such as `.` and `..` will be included in the return
    /// values.
    ///
    /// Also note that the return paths will not be absolute paths, they are
    /// the filenames of the files in this directory.
    pub fn readdir(&mut self) -> Result<(PathBuf, FileStat), Error> {
        let mut buf = Vec::<u8>::with_capacity(128);
        let mut stat = unsafe { mem::zeroed() };
        let mut rc;
        loop {
            rc = unsafe {
                raw::libssh2_sftp_readdir_ex(self.raw,
                                             buf.as_mut_ptr() as *mut _,
                                             buf.capacity() as size_t,
                                             0 as *mut _, 0,
                                             &mut stat)
            };
            if rc == raw::LIBSSH2_ERROR_BUFFER_TOO_SMALL {
                let cap = buf.capacity();
                buf.reserve(cap);
            } else {
                break
            }
        }
        if rc < 0 {
            return Err(self.sftp.last_error())
        } else if rc == 0 {
            return Err(Error::new(raw::LIBSSH2_ERROR_FILE, "no more files"))
        } else {
            unsafe { buf.set_len(rc as usize); }
        }
        Ok((mkpath(buf), FileStat::from_raw(&stat)))
    }

    /// This function causes the remote server to synchronize the file data and
    /// metadata to disk (like fsync(2)).
    ///
    /// For this to work requires fsync@openssh.com support on the server.
    pub fn fsync(&mut self) -> Result<(), Error> {
        self.sftp.rc(unsafe { raw::libssh2_sftp_fsync(self.raw) })
    }
}

impl<'sftp> Read for File<'sftp> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let rc = raw::libssh2_sftp_read(self.raw,
                                            buf.as_mut_ptr() as *mut _,
                                            buf.len() as size_t);
            match rc {
                n if n < 0 => Err(io::Error::new(ErrorKind::Other,
                                                 self.sftp.last_error())),
                n => Ok(n as usize)
            }
        }
    }
}

impl<'sftp> Write for File<'sftp> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let rc = unsafe {
            raw::libssh2_sftp_write(self.raw,
                                    buf.as_ptr() as *const _,
                                    buf.len() as size_t)
        };
        if rc < 0 {
            Err(io::Error::new(ErrorKind::Other, self.sftp.last_error()))
        } else {
            Ok(rc as usize)
        }
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<'sftp> Seek for File<'sftp> {
    /// Move the file handle's internal pointer to an arbitrary location.
    ///
    /// libssh2 implements file pointers as a localized concept to make file
    /// access appear more POSIX like. No packets are exchanged with the server
    /// during a seek operation. The localized file pointer is simply used as a
    /// convenience offset during read/write operations.
    ///
    /// You MUST NOT seek during writing or reading a file with SFTP, as the
    /// internals use outstanding packets and changing the "file position"
    /// during transit will results in badness.
    fn seek(&mut self, how: SeekFrom) -> io::Result<u64> {
        let next = match how {
            SeekFrom::Start(pos) => pos,
            SeekFrom::Current(offset) => {
                let cur = unsafe { raw::libssh2_sftp_tell64(self.raw) };
                (cur as i64 + offset) as u64
            }
            SeekFrom::End(offset) => match self.stat() {
                Ok(s) => match s.size {
                    Some(size) => (size as i64 + offset) as u64,
                    None => {
                        return Err(io::Error::new(ErrorKind::Other,
                                                  "no file size available"))
                    }
                },
                Err(e) => {
                    return Err(io::Error::new(ErrorKind::Other, e))
                }
            }
        };
        unsafe { raw::libssh2_sftp_seek64(self.raw, next) }
        Ok(next)
    }
}

impl<'sftp> Drop for File<'sftp> {
    fn drop(&mut self) {
        unsafe { assert_eq!(raw::libssh2_sftp_close_handle(self.raw), 0) }
    }
}

impl FileStat {
    /// Returns the file type for this filestat.
    pub fn file_type(&self) -> FileType {
        FileType { perm: self.perm.unwrap_or(0) as c_ulong }
    }

    /// Returns whether this metadata is for a directory.
    pub fn is_dir(&self) -> bool { self.file_type().is_dir() }

    /// Returns whether this metadata is for a regular file.
    pub fn is_file(&self) -> bool { self.file_type().is_file() }

    /// Creates a new instance of a stat from a raw instance.
    pub fn from_raw(raw: &raw::LIBSSH2_SFTP_ATTRIBUTES) -> FileStat {
        fn val<T: Copy>(raw: &raw::LIBSSH2_SFTP_ATTRIBUTES, t: &T,
                        flag: c_ulong) -> Option<T> {
            if raw.flags & flag != 0 {Some(*t)} else {None}
        }

        FileStat {
            size: val(raw, &raw.filesize, raw::LIBSSH2_SFTP_ATTR_SIZE),
            uid: val(raw, &raw.uid, raw::LIBSSH2_SFTP_ATTR_UIDGID)
                    .map(|s| s as u32),
            gid: val(raw, &raw.gid, raw::LIBSSH2_SFTP_ATTR_UIDGID)
                    .map(|s| s as u32),
            perm: val(raw, &raw.permissions, raw::LIBSSH2_SFTP_ATTR_PERMISSIONS)
                     .map(|s| s as u32),
            mtime: val(raw, &raw.mtime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME)
                      .map(|s| s as u64),
            atime: val(raw, &raw.atime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME)
                      .map(|s| s as u64),
        }
    }

    /// Convert this stat structure to its raw representation.
    pub fn raw(&self) -> raw::LIBSSH2_SFTP_ATTRIBUTES {
        fn flag<T>(o: &Option<T>, flag: c_ulong) -> c_ulong {
            if o.is_some() {flag} else {0}
        }

        raw::LIBSSH2_SFTP_ATTRIBUTES {
            flags: flag(&self.size, raw::LIBSSH2_SFTP_ATTR_SIZE) |
                   flag(&self.uid, raw::LIBSSH2_SFTP_ATTR_UIDGID) |
                   flag(&self.gid, raw::LIBSSH2_SFTP_ATTR_UIDGID) |
                   flag(&self.perm, raw::LIBSSH2_SFTP_ATTR_PERMISSIONS) |
                   flag(&self.atime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME) |
                   flag(&self.mtime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME),
            filesize: self.size.unwrap_or(0),
            uid: self.uid.unwrap_or(0) as c_ulong,
            gid: self.gid.unwrap_or(0) as c_ulong,
            permissions: self.perm.unwrap_or(0) as c_ulong,
            atime: self.atime.unwrap_or(0) as c_ulong,
            mtime: self.mtime.unwrap_or(0) as c_ulong,
        }
    }
}

impl FileType {
    /// Test whether this file type represents a directory.
    pub fn is_dir(&self) -> bool { self.is(raw::LIBSSH2_SFTP_S_IFDIR) }

    /// Test whether this file type represents a regular file.
    pub fn is_file(&self) -> bool { self.is(raw::LIBSSH2_SFTP_S_IFREG) }

    /// Test whether this file type represents a symbolic link.
    pub fn is_symlink(&self) -> bool { self.is(raw::LIBSSH2_SFTP_S_IFLNK) }

    fn is(&self, perm: c_ulong) -> bool {
        (self.perm & raw::LIBSSH2_SFTP_S_IFMT) == perm
    }
}

#[cfg(unix)]
fn mkpath(v: Vec<u8>) -> PathBuf {
    use std::os::unix::prelude::*;
    use std::ffi::OsStr;
    PathBuf::from(OsStr::from_bytes(&v))
}
#[cfg(windows)]
fn mkpath(v: Vec<u8>) -> PathBuf {
    use std::str;
    PathBuf::from(str::from_utf8(&v).unwrap())
}
