use std::borrow::Cow;
use std::path::{Path, PathBuf};

use {raw, Error, ErrorCode};

#[cfg(unix)]
pub fn path2bytes(p: &Path) -> Result<Cow<'_, [u8]>, Error> {
    use std::ffi::OsStr;
    use std::os::unix::prelude::*;
    let s: &OsStr = p.as_ref();
    check(Cow::Borrowed(s.as_bytes()))
}
#[cfg(windows)]
pub fn path2bytes(p: &Path) -> Result<Cow<'_, [u8]>, Error> {
    p.to_str()
        .map(|s| s.as_bytes())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Session(raw::LIBSSH2_ERROR_INVAL),
                "only unicode paths on windows may be used",
            )
        })
        .map(|bytes| {
            if bytes.contains(&b'\\') {
                // Normalize to Unix-style path separators
                let mut bytes = bytes.to_owned();
                for b in &mut bytes {
                    if *b == b'\\' {
                        *b = b'/';
                    }
                }
                Cow::Owned(bytes)
            } else {
                Cow::Borrowed(bytes)
            }
        })
        .and_then(check)
}

#[cfg(unix)]
pub fn mkpath(bytes: &[u8]) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::prelude::*;
    PathBuf::from(OsStr::from_bytes(bytes))
}
#[cfg(windows)]
pub fn mkpath(bytes: &[u8]) -> PathBuf {
    use std::str;
    PathBuf::from(str::from_utf8(bytes).unwrap())
}

fn check(b: Cow<[u8]>) -> Result<Cow<[u8]>, Error> {
    if b.iter().any(|b| *b == 0) {
        Err(Error::new(
            ErrorCode::Session(raw::LIBSSH2_ERROR_INVAL),
            "path provided contains a 0 byte",
        ))
    } else {
        Ok(b)
    }
}
