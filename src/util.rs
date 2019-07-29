use std::borrow::Cow;
use std::path::Path;

use {raw, Error};

#[doc(hidden)]
pub trait Binding: Sized {
    type Raw;

    unsafe fn from_raw(raw: Self::Raw) -> Self;
    fn raw(&self) -> Self::Raw;
}

#[cfg(unix)]
pub fn path2bytes(p: &Path) -> Result<Cow<[u8]>, Error> {
    use std::ffi::OsStr;
    use std::os::unix::prelude::*;
    let s: &OsStr = p.as_ref();
    check(Cow::Borrowed(s.as_bytes()))
}
#[cfg(windows)]
pub fn path2bytes(p: &Path) -> Result<Cow<[u8]>, Error> {
    p.to_str()
        .map(|s| s.as_bytes())
        .ok_or_else(|| {
            Error::new(
                raw::LIBSSH2_ERROR_INVAL,
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

fn check(b: Cow<[u8]>) -> Result<Cow<[u8]>, Error> {
    if b.iter().any(|b| *b == 0) {
        Err(Error::new(
            raw::LIBSSH2_ERROR_INVAL,
            "path provided contains a 0 byte",
        ))
    } else {
        Ok(b)
    }
}
