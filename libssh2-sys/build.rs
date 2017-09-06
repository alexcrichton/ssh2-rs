extern crate pkg_config;
extern crate cmake;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::{PathBuf, Path};
use std::process::Command;

fn main() {
    if try_vcpkg() {
        return;
    }

    register_dep("Z");
    register_dep("OPENSSL");

    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();

    if target != host {
        let lib_dir = env::var_os("TARGET_LIBSSH2_LIB_DIR").map(PathBuf::from);
        let include_dir = env::var_os("TARGET_LIBSSH2_INCLUDE_DIR").map(PathBuf::from);

        if lib_dir.is_some() && include_dir.is_some() {
            println!("cargo:rustc-link-search=native={}", lib_dir.unwrap().to_string_lossy());
            println!("cargo:include={}", include_dir.unwrap().to_string_lossy());
            println!("cargo:rustc-link-lib=dylib=ssh2");
            return;
        }
    }

    if let Ok(lib) = pkg_config::find_library("libssh2") {
        for path in &lib.include_paths {
            println!("cargo:include={}", path.display());
        }
        return
    }

    if !Path::new("libssh2/.git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init"])
                                   .status();
    }

    let mut cfg = cmake::Config::new("libssh2");

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

    if let Some(path) = env::var_os("DEP_OPENSSL_INCLUDE") {
        if let Some(path) = env::split_paths(&path).next() {
            if let Some(path) = path.to_str() {
                if path.len() > 0 {
                    cfg.define("OPENSSL_INCLUDE_DIR", path);
                }
            }
        }
    }

    // Homebrew deprecated OpenSSL and deliberately hides it from cmake, requiring such opt-in
    if target.contains("darwin") && Path::new("/usr/local/opt/openssl/include/openssl/ssl.h").exists() {
        cfg.define("OPENSSL_ROOT_DIR", "/usr/local/opt/openssl/");
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

fn register_dep(dep: &str) {
    if let Some(s) = env::var_os(&format!("DEP_{}_ROOT", dep)) {
        prepend("PKG_CONFIG_PATH", Path::new(&s).join("lib/pkgconfig"));
        return
    }
    if let Some(s) = env::var_os(&format!("DEP_{}_INCLUDE", dep)) {
        let root = Path::new(&s).parent().unwrap();
        env::set_var(&format!("DEP_{}_ROOT", dep), root);
        let path = root.join("lib/pkgconfig");
        if path.exists() {
            prepend("PKG_CONFIG_PATH", path);
            return
        }
    }
}

fn prepend(var: &str, val: PathBuf) {
    let prefix = env::var(var).unwrap_or(String::new());
    let mut v = vec![val];
    v.extend(env::split_paths(&prefix));
    env::set_var(var, &env::join_paths(v).unwrap());
}

#[cfg(not(target_env = "msvc"))]
fn try_vcpkg() -> bool { false }

#[cfg(target_env = "msvc")]
fn try_vcpkg() -> bool {
    vcpkg::Config::new()
        .emit_includes(true)
        .probe("libssh2").map(|_| {

        // found libssh2 which depends on openssl and zlib
        vcpkg::Config::new()
            .lib_name("libeay32")
            .lib_name("ssleay32")
            .probe("openssl").expect("configured libssh2 from vcpkg but could not \
                                      find openssl libraries that it depends on");

        vcpkg::Config::new()
            .lib_names("zlib", "zlib1")
            .probe("zlib").expect("configured libssh2 from vcpkg but could not \
                                   find the zlib library that it depends on");

        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=user32");
    }).is_ok()
}
