use std::path::Path;

use {raw, Session, Error};

#[doc(hidden)]
pub trait Binding: Sized {
    type Raw;

    unsafe fn from_raw(raw: Self::Raw) -> Self;
    fn raw(&self) -> Self::Raw;
}

#[doc(hidden)]
pub trait SessionBinding<'sess>: Sized {
    type Raw;

    unsafe fn from_raw(sess: &'sess Session, raw: *mut Self::Raw) -> Self;
    fn raw(&self) -> *mut Self::Raw;

    unsafe fn from_raw_opt(sess: &'sess Session, raw: *mut Self::Raw)
                           -> Result<Self, Error> {
        if raw.is_null() {
            Err(Error::last_error(sess).unwrap())
        } else {
            Ok(SessionBinding::from_raw(sess, raw))
        }
    }
}

#[cfg(unix)]
pub fn path2bytes(p: &Path) -> Result<&[u8], Error> {
    use std::os::unix::prelude::*;
    use std::ffi::OsStr;
    let s: &OsStr = p.as_ref();
    check(s.as_bytes())
}
#[cfg(windows)]
pub fn path2bytes(p: &Path) -> Result<&[u8], Error> {
    match p.to_str() {
        Some(s) => check(s),
        None => Error::new(raw::LIBSSH2_ERROR_INVAL,
                           "only unicode paths on windows may be used"),
    }
}

fn check(b: &[u8]) -> Result<&[u8], Error> {
    if b.iter().any(|b| *b == 0) {
        Err(Error::new(raw::LIBSSH2_ERROR_INVAL,
                       "path provided contains a 0 byte"))
    } else {
        Ok(b)
    }
}
