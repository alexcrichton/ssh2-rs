use {Session, Error};

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
