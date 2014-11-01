extern crate "pkg-config" as pkg_config;

use std::os;
use std::io::{mod, fs, Command};
use std::io::process::InheritFd;

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
    fs::mkdir(&dst.join("build"), io::USER_DIR).unwrap();

    let root = src.join("libssh2-1.4.4-20140901");
    run(Command::new(root.join("configure"))
                .env("CFLAGS", cflags)
                .args(config_opts.as_slice())
                .cwd(&dst.join("build")));
    run(Command::new(make())
                .arg(format!("-j{}", os::getenv("NUM_JOBS").unwrap()))
                .cwd(&dst.join("build/src")));

    // Don't run `make install` because apparently it's a little buggy on mingw
    // for windows.
    fs::mkdir_recursive(&dst.join("lib/pkgconfig"), io::USER_DIR).unwrap();
    let filename = if windows {"libssh2.lib"} else {"libssh2.a"};
    fs::rename(&dst.join("build/src/.libs").join(filename),
               &dst.join("lib/libssh2.a")).unwrap();
    fs::rename(&dst.join("build/libssh2.pc"),
               &dst.join("lib/pkgconfig/libssh2.pc")).unwrap();

    {
        let root = root.join("include");
        let dst = dst.join("include");
        for file in fs::walk_dir(&root).unwrap() {
            if fs::stat(&file).unwrap().kind != io::TypeFile { continue }

            let part = file.path_relative_from(&root).unwrap();
            let dst = dst.join(part);
            fs::mkdir_recursive(&dst.dir_path(), io::USER_DIR).unwrap();
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
    println!("running: {}", cmd);
    assert!(cmd.stdout(InheritFd(1))
               .stderr(InheritFd(2))
               .status()
               .unwrap()
               .success());

}
