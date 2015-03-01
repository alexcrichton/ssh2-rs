#![feature(io, path, core, fs, process)]

extern crate "pkg-config" as pkg_config;

use std::env;
use std::fs;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::Command;

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
    } else if target.as_slice().contains("x86_64") {
        cflags.push_str(" -m64");
    }
    if !target.contains("i686") {
        cflags.push_str(" -fPIC");
    }

    match env::var("DEP_OPENSSL_ROOT") {
        Ok(s) => {
            cflags.push_str(format!(" -I{}/include", s).as_slice());
            cflags.push_str(format!(" -L{}/lib", s).as_slice());
        }
        Err(..) => {}
    }

    let src = PathBuf::new(&env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let dst = PathBuf::new(&env::var_os("OUT_DIR").unwrap());

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
    fs::create_dir(&dst.join("build")).unwrap();

    let root = src.join("libssh2-1.4.4-20140901");
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
    fs::create_dir_all(&dst.join("lib/pkgconfig")).unwrap();

    // Which one does windows generate? Who knows!
    let p1 = dst.join("build/src/.libs/libssh2.a");
    let p2 = dst.join("build/src/.libs/libssh2.lib");
    if p1.exists() {
        fs::rename(&p1, &dst.join("lib/libssh2.a")).unwrap();
    } else {
        fs::rename(&p2, &dst.join("lib/libssh2.a")).unwrap();
    }
    fs::rename(&dst.join("build/libssh2.pc"),
               &dst.join("lib/pkgconfig/libssh2.pc")).unwrap();

    {
        let root = root.join("include");
        let dst = dst.join("include");
        for file in fs::walk_dir(&root).unwrap() {
            let file = file.unwrap().path();
            if !file.is_file() { continue }

            let part = file.relative_from(&root).unwrap();
            let dst = dst.join(part);
            fs::create_dir_all(dst.parent().unwrap()).unwrap();
            fs::copy(&file, &dst).unwrap();
        }
    }

    if windows {
        println!("cargo:rustc-flags=-l ws2_32 -l bcrypt -l crypt32");
    }
    println!("cargo:rustc-flags=-L {}/lib -l ssh2:static", dst.display());
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}/include", dst.display());
}

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(cmd.status().unwrap().success());
}

fn which(cmd: &str) -> Option<PathBuf> {
    let cmd = format!("{}{}", cmd, env::consts::EXE_SUFFIX);
    env::split_paths(&env::var("PATH").unwrap()).map(|p| {
        p.join(&cmd)
    }).find(|p| p.exists())
}
