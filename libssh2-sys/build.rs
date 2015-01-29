#![feature(io, path, os, collections, core)]

extern crate "pkg-config" as pkg_config;

use std::os;
use std::old_io::{self, fs, Command};
use std::old_io::process::InheritFd;
use std::old_io::fs::PathExtensions;

fn main() {
    match pkg_config::find_library("libssh2") {
        Ok(()) => return,
        Err(..) => {}
    }

    let mut cflags = os::getenv("CFLAGS").unwrap_or(String::new());
    let target = os::getenv("TARGET").unwrap();
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

    match os::getenv("DEP_OPENSSL_ROOT") {
        Some(s) => {
            cflags.push_str(format!(" -I{}/include", s).as_slice());
            cflags.push_str(format!(" -L{}/lib", s).as_slice());
        }
        None => {}
    }

    let src = Path::new(os::getenv("CARGO_MANIFEST_DIR").unwrap());
    let dst = Path::new(os::getenv("OUT_DIR").unwrap());

    let mut config_opts = Vec::new();
    if windows {
        config_opts.push("--without-openssl".to_string());
        config_opts.push("--with-wincng".to_string());
    }
    config_opts.push("--enable-shared=no".to_string());
    config_opts.push("--disable-examples-build".to_string());
    config_opts.push(format!("--prefix={}", dst.display()));

    let _ = fs::rmdir_recursive(&dst.join("include"));
    let _ = fs::rmdir_recursive(&dst.join("lib"));
    let _ = fs::rmdir_recursive(&dst.join("build"));
    fs::mkdir(&dst.join("build"), old_io::USER_DIR).unwrap();

    let root = src.join("libssh2-1.4.4-20140901");
    // Can't run ./configure directly on msys2 b/c we're handing in
    // Windows-style paths (those starting with C:\), but it chokes on those.
    // For that reason we build up a shell script with paths converted to
    // posix versions hopefully...
    //
    // Also apparently the buildbots choke unless we manually set LD, who knows
    // why?!
    run(Command::new("sh")
                .env("CFLAGS", cflags)
                .env("LD", which("ld").unwrap())
                .cwd(&dst.join("build"))
                .arg("-c")
                .arg(format!("{} {}", root.join("configure").display(),
                             config_opts.connect(" "))
                            .replace("C:\\", "/c/")
                            .replace("\\", "/")));
    run(Command::new(make())
                .arg(format!("-j{}", os::getenv("NUM_JOBS").unwrap()))
                .cwd(&dst.join("build/src")));

    // Don't run `make install` because apparently it's a little buggy on mingw
    // for windows.
    fs::mkdir_recursive(&dst.join("lib/pkgconfig"), old_io::USER_DIR).unwrap();

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
            if fs::stat(&file).unwrap().kind != old_io::FileType::RegularFile { continue }

            let part = file.path_relative_from(&root).unwrap();
            let dst = dst.join(part);
            fs::mkdir_recursive(&dst.dir_path(), old_io::USER_DIR).unwrap();
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
    assert!(cmd.stdout(InheritFd(1))
               .stderr(InheritFd(2))
               .status()
               .unwrap()
               .success());

}

fn which(cmd: &str) -> Option<Path> {
    let cmd = format!("{}{}", cmd, os::consts::EXE_SUFFIX);
    let paths = os::split_paths(os::getenv("PATH").unwrap());
    paths.iter().map(|p| p.join(&cmd)).find(|p| p.exists())
}
