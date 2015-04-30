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
    let args = env::args_os();

    // Oh boy! If we're compiling on MSVC, then it turns out this build script
    // itself is going to be used as a compiler! Currently the nmake build
    // files for libssh2 *always* add the /GL compiler option to compiler
    // invocations to enable whole program optimization.
    //
    // Unfortunately this requires the linker be passed /LTCG as a parameter,
    // and we don't currently have a great way of passing that parameter to the
    // Rust compiler itself. As such, this script uses itself as a compiler for
    // the MSVC code and passes the /GL- option to disable whole program
    // optimization, allowing the linker to succeed.
    if args.len() > 1 {
        let args = args.collect::<Vec<_>>();
        assert!(Command::new("cl").args(&args)
                                  .arg("/GL-")
                                  .status().unwrap()
                                  .success());
        return
    }

    match pkg_config::find_library("libssh2") {
        Ok(..) => return,
        Err(..) => {}
    }

    let mut cflags = env::var("CFLAGS").unwrap_or(String::new());
    let target = env::var("TARGET").unwrap();
    let windows = target.contains("windows");
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

    let dst = PathBuf::from(&env::var_os("OUT_DIR").unwrap());
    let root = t!(env::current_dir()).join("libssh2-1.5.0");

    let _ = fs::remove_dir_all(&dst.join("include"));
    let _ = fs::remove_dir_all(dst.join("lib"));
    let _ = fs::remove_dir_all(dst.join("build"));
    t!(fs::create_dir(dst.join("build")));

    if !windows {
        run(Command::new(root.join("configure"))
                    .env("CFLAGS", &cflags)
                    .current_dir(dst.join("build"))
                    .arg("--enable-shared=no")
                    .arg("--disable-examples-build")
                    .arg(format!("--prefix={}", dst.display())));
        run(Command::new(&make())
                    .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
                    .current_dir(dst.join("build/src")));
        run(Command::new(&make())
                    .arg("install")
                    .current_dir(dst.join("build/src")));
        run(Command::new(&make())
                    .arg("install-data")
                    .current_dir(dst.join("build")));

        // Unfortunately the pkg-config file generated for libssh2 indicates
        // that it depends on zlib, but most systems don't actually have a
        // zlib.pc, so pkg-config will say that libssh2 doesn't exist. We
        // generally take care of the zlib dependency elsewhere, so we just
        // remove that part from the pkg-config file
        let mut pc = String::new();
        let pkgconfig = dst.join("lib/pkgconfig/libssh2.pc");
        t!(t!(File::open(&pkgconfig)).read_to_string(&mut pc));
        let pc = pc.replace(",zlib", "");
        let bytes = pc.as_bytes();
        t!(t!(File::create(pkgconfig)).write_all(bytes));

    } else {
        t!(fs::create_dir(dst.join("lib")));

        if target.contains("msvc") {
            run(Command::new("nmake")
                        .current_dir(&root)
                        .arg("/nologo")
                        // see above for why we set CC here
                        .env("CC", env::current_exe().unwrap())
                        .env_remove("TARGET")
                        .arg("/fNMakefile")
                        .arg("BUILD_STATIC_LIB=1")
                        .arg("WITH_WINCNG=1"));
            t!(fs::copy(root.join("Release/src/libssh2.lib"),
                        dst.join("lib/libssh2.a")));
            t!(fs::remove_dir_all(root.join("Release")));
        } else {
            run(Command::new("make")
                        .current_dir(root.join("win32"))
                        .arg("-fGNUmakefile")
                        .arg("WITH_WINCNG=1")
                        .arg("WITH_ZLIB=1")
                        .arg("lib"));
            t!(fs::remove_dir_all(root.join("win32/release")));
            t!(fs::copy(root.join("win32/libssh2.a"), dst.join("lib/libssh2.a")));
            t!(fs::remove_file(root.join("win32/libssh2.a")));
        }

        let root = root.join("include");
        let dst = dst.join("include");
        t!(fs::create_dir_all(&dst));
        t!(fs::copy(root.join("libssh2.h"), dst.join("libssh2.h")));
        t!(fs::copy(root.join("libssh2_publickey.h"),
                    dst.join("libssh2_publickey.h")));
        t!(fs::copy(root.join("libssh2_sftp.h"), dst.join("libssh2_sftp.h")));
    }

    if windows {
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

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    let status = t!(cmd.status());
    if !status.success() {
        panic!("command did not succeed, exited with: {}", status);
    }
}
