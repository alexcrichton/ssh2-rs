#![allow(bad_style, improper_ctypes)]

extern crate libc;
extern crate libssh2_sys;

use libc::*;
use libssh2_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
