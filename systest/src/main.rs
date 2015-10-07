#![allow(bad_style, improper_ctypes)]

extern crate libssh2_sys;
extern crate libc;

use libc::*;
use libssh2_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
