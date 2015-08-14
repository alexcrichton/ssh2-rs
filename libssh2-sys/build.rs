extern crate pkg_config;
extern crate cmake;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() {
    if let Ok(lib) = pkg_config::find_library("libssh2") {
        for path in &lib.include_paths {
            println!("cargo:include={}", path.display());
        }
        return
    }

    let mut cfg = cmake::Config::new("libssh2");

    let target = env::var("TARGET").unwrap();

    // Don't use OpenSSL on Windows, instead use the native Windows backend.
    if target.contains("windows") {
        cfg.define("CRYPTO_BACKEND", "WinCNG");
    } else {
        cfg.define("CRYPTO_BACKEND", "OpenSSL");
    }

    // If libz-sys was built it'll give us an include directory to learn how to
    // link to it, and for MinGW targets we just pass a dummy include dir to
    // ensure it's detected (apparently it isn't otherwise?)
    match env::var_os("DEP_Z_INCLUDE") {
        Some(path) => { cfg.define("ZLIB_INCLUDE_DIR", path); }
        None if target.contains("windows-gnu") => {
            cfg.define("ZLIB_INCLUDE_DIR", "/");
        }
        None => {}
    }

    // MSVC targets also need us to tell libssh2's cmake exactly where zlib is
    // installed, so learn that through the ROOT metadata.
    if let Some(path) = env::var_os("DEP_Z_ROOT") {
        let path = PathBuf::from(path);
        if target.contains("msvc") {
            cfg.define("ZLIB_LIBRARY", path.join("lib/zlib.lib"));
        }
    }

    let dst = cfg.define("BUILD_SHARED_LIBS", "OFF")
                 .define("ENABLE_ZLIB_COMPRESSION", "ON")
                 .define("CMAKE_INSTALL_LIBDIR", "lib")
                 .define("BUILD_EXAMPLES", "OFF")
                 .define("BUILD_TESTING", "OFF")
                 .register_dep("OPENSSL")
                 .register_dep("Z")
                 .build();

    // Unfortunately the pkg-config file generated for libssh2 indicates
    // that it depends on zlib, but most systems don't actually have a
    // zlib.pc, so pkg-config will say that libssh2 doesn't exist. We
    // generally take care of the zlib dependency elsewhere, so we just
    // remove that part from the pkg-config file
    let mut pc = String::new();
    let pkgconfig = dst.join("lib/pkgconfig/libssh2.pc");
    if let Ok(mut f) = File::open(&pkgconfig) {
        f.read_to_string(&mut pc).unwrap();;
        drop(f);
        let pc = pc.replace(",zlib", "");
        let bytes = pc.as_bytes();
        File::create(pkgconfig).unwrap().write_all(bytes).unwrap();
    }

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=user32");
    }

    // msvc generates libssh2.lib, everywhere else generates libssh2.a
    if target.contains("msvc") {
        println!("cargo:rustc-link-lib=static=libssh2");
    } else {
        println!("cargo:rustc-link-lib=static=ssh2");
    }
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:include={}/include", dst.display());
}
