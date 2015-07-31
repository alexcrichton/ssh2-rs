extern crate pkg_config;
extern crate cmake;

use std::env;
use std::path::PathBuf;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(n) => n,
        Err(e) => panic!("\n{} failed with {}\n", stringify!($e), e),
    })
}

fn main() {
    if let Ok(lib) = pkg_config::find_library("libssh2") {
        for path in &lib.include_paths {
            println!("cargo:include={}", path.display());
        }
        return
    }

    let mut cfg = cmake::Config::new("libssh2");

    let target = env::var("TARGET").unwrap();
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    if target.contains("windows") {
        cfg.define("CRYPTO_BACKEND", "WinCNG");
    } else {
        cfg.define("CRYPTO_BACKEND", "OpenSSL");
    }
    let zlib = if target.contains("windows") {"OFF"} else {"ON"};
    cfg.define("BUILD_SHARED_LIBS", "OFF")
       .define("ENABLE_ZLIB_COMPRESSION", zlib)
       .define("CMAKE_INSTALL_LIBDIR", dst.join("lib"))
       .define("BUILD_EXAMPLES", "OFF")
       .define("BUILD_TESTING", "OFF")
       .register_dep("OPENSSL")
       .build();

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=user32");
    }
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=ssh2");
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}/include", dst.display());
}
