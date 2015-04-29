extern crate pkg_config;

use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::Command;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(n) => n,
        Err(e) => panic!("\n{} failed with {}\n", stringify!($e), e),
    })
}

fn main() {
    match pkg_config::find_library("libssh2") {
        Ok(..) => return,
        Err(..) => {}
    }

    let mut cflags = env::var("CFLAGS").unwrap_or(String::new());
    let target = env::var("TARGET").unwrap();
    let windows = target.contains("windows") || target.contains("mingw");
    cflags.push_str(" -ffunction-sections -fdata-sections");

    if target.contains("i686") {
        cflags.push_str(" -m32");
    } else if target.contains("x86_64") {
        cflags.push_str(" -m64");
    }
    if !target.contains("i686") {
        cflags.push_str(" -fPIC");
    }

    match env::var("DEP_OPENSSL_ROOT") {
        Ok(s) => {
            cflags.push_str(&format!(" -I{}/include", s));
            cflags.push_str(&format!(" -L{}/lib", s));
        }
        Err(..) => {}
    }

    let src = PathBuf::from(&env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let dst = PathBuf::from(&env::var_os("OUT_DIR").unwrap());

    let mut config_opts = Vec::new();
    if windows {
        config_opts.push("--without-openssl".to_string());
        config_opts.push("--with-wincng".to_string());
    }
    config_opts.push("--enable-shared=no".to_string());
    config_opts.push("--disable-examples-build".to_string());
    config_opts.push(format!("--prefix={}", dst.display()));

    let _ = fs::remove_dir_all(&dst.join("include"));
    let _ = fs::remove_dir_all(&dst.join("lib"));
    let _ = fs::remove_dir_all(&dst.join("build"));
    t!(fs::create_dir(&dst.join("build")));

    let root = src.join("libssh2-1.5.0");
    // Can't run ./configure directly on msys2 b/c we're handing in
    // Windows-style paths (those starting with C:\), but it chokes on those.
    // For that reason we build up a shell script with paths converted to
    // posix versions hopefully...
    //
    // Also apparently the buildbots choke unless we manually set LD, who knows
    // why?!
    run(Command::new("sh")
                .env("CFLAGS", &cflags)
                .env("LD", &which("ld").unwrap())
                .current_dir(&dst.join("build"))
                .arg("-c")
                .arg(&format!("{} {}", root.join("configure").display(),
                              config_opts.connect(" "))
                             .replace("C:\\", "/c/")
                             .replace("\\", "/")));
    run(Command::new(&make())
                .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
                .current_dir(&dst.join("build/src")));

    // Don't run `make install` because apparently it's a little buggy on mingw
    // for windows.
    t!(fs::create_dir_all(&dst.join("lib/pkgconfig")));

    // Which one does windows generate? Who knows!
    let p1 = dst.join("build/src/.libs/libssh2.a");
    let p2 = dst.join("build/src/.libs/libssh2.lib");
    if fs::metadata(&p1).is_ok() {
        t!(fs::copy(&p1, &dst.join("lib/libssh2.a")));
    } else {
        t!(fs::copy(&p2, &dst.join("lib/libssh2.a")));
    }

    // Unfortunately the pkg-config file generated for libssh2 indicates that it
    // depends on zlib, but most systems don't actually have a zlib.pc, so
    // pkg-config will say that libssh2 doesn't exist. We generally take care of
    // the zlib dependency elsewhere, so we just remove that part from the
    // pkg-config file
    let mut pc = String::new();
    t!(t!(File::open(dst.join("build/libssh2.pc"))).read_to_string(&mut pc));
    let pc = pc.replace(",zlib", "");
    let bytes = pc.as_bytes();
    t!(t!(File::create(dst.join("lib/pkgconfig/libssh2.pc"))).write_all(bytes));

    {
        let root = root.join("include");
        let dst = dst.join("include");
        t!(fs::create_dir_all(&dst));
        t!(fs::copy(&root.join("libssh2.h"), &dst.join("libssh2.h")));
        t!(fs::copy(&root.join("libssh2_publickey.h"),
                    &dst.join("libssh2_publickey.h")));
        t!(fs::copy(&root.join("libssh2_sftp.h"), &dst.join("libssh2_sftp.h")));
    }

    if windows {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
    }
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=ssh2");
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}/include", dst.display());
}

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(t!(cmd.status()).success());
}

fn which(cmd: &str) -> Option<PathBuf> {
    let cmd = format!("{}{}", cmd, env::consts::EXE_SUFFIX);
    env::split_paths(&env::var("PATH").unwrap()).map(|p| {
        p.join(&cmd)
    }).find(|p| fs::metadata(p).is_ok())
}
