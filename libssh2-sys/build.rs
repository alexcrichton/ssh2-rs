extern crate pkg_config;
extern crate cc;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::fs;
use std::env;
use std::path::{PathBuf, Path};
use std::process::Command;

fn main() {
    if try_vcpkg() {
        return;
    }

    // The system copy of libssh2 is not used by default because it
    // can lead to having two copies of libssl loaded at once.
    // See https://github.com/alexcrichton/ssh2-rs/pull/88
    if env::var("LIBSSH2_SYS_USE_PKG_CONFIG").is_ok() {
        if let Ok(lib) = pkg_config::find_library("libssh2") {
            for path in &lib.include_paths {
                println!("cargo:include={}", path.display());
            }
            return
        }
    }

    if !Path::new("libssh2/.git").exists() {
        let _ = Command::new("git").args(&["submodule", "update", "--init"])
                                   .status();
    }

    let target = env::var("TARGET").unwrap();
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut cfg = cc::Build::new();

    let include = dst.join("include");
    println!("cargo:include={}", include.display());
    println!("cargo:root={}", dst.display());
    let build = dst.join("build");
    cfg.out_dir(&build);
    fs::create_dir_all(&build).unwrap();
    fs::create_dir_all(&include).unwrap();

    fs::copy("libssh2/include/libssh2.h", include.join("libssh2.h")).unwrap();
    fs::copy("libssh2/include/libssh2_publickey.h", include.join("libssh2_publickey.h")).unwrap();
    fs::copy("libssh2/include/libssh2_sftp.h", include.join("libssh2_sftp.h")).unwrap();

    cfg.file("libssh2/src/agent.c")
        .file("libssh2/src/bcrypt_pbkdf.c")
        .file("libssh2/src/blowfish.c")
        .file("libssh2/src/channel.c")
        .file("libssh2/src/comp.c")
        .file("libssh2/src/crypt.c")
        .file("libssh2/src/global.c")
        .file("libssh2/src/hostkey.c")
        .file("libssh2/src/keepalive.c")
        .file("libssh2/src/kex.c")
        .file("libssh2/src/knownhost.c")
        .file("libssh2/src/mac.c")
        .file("libssh2/src/misc.c")
        .file("libssh2/src/packet.c")
        .file("libssh2/src/pem.c")
        .file("libssh2/src/publickey.c")
        .file("libssh2/src/scp.c")
        .file("libssh2/src/session.c")
        .file("libssh2/src/sftp.c")
        .file("libssh2/src/transport.c")
        .file("libssh2/src/userauth.c")
        .include(&include)
        .include("libssh2/src");

    cfg.define("HAVE_LONGLONG", None);

    if target.contains("windows") {
        cfg.include("libssh2/win32");
        cfg.define("LIBSSH2_WINCNG", None);
        cfg.file("libssh2/src/wincng.c");
    } else {
        cfg.flag("-fvisibility=hidden");
        cfg.define("HAVE_SNPRINTF", None);
        cfg.define("HAVE_UNISTD_H", None);
        cfg.define("HAVE_INTTYPES_H", None);
        cfg.define("HAVE_STDLIB_H", None);
        cfg.define("HAVE_SYS_SELECT_H", None);
        cfg.define("HAVE_SYS_SOCKET_H", None);
        cfg.define("HAVE_SYS_IOCTL_H", None);
        cfg.define("HAVE_SYS_TIME_H", None);
        cfg.define("HAVE_SYS_UN_H", None);
        cfg.define("HAVE_O_NONBLOCK", None);
        cfg.define("LIBSSH2_OPENSSL", None);
        cfg.define("HAVE_LIBCRYPT32", None);
        cfg.define("HAVE_EVP_AES_128_CTR", None);

        cfg.file("libssh2/src/openssl.c");

        // Create `libssh2_config.h`
        let config = fs::read_to_string("libssh2/src/libssh2_config_cmake.h.in")
            .unwrap();
        let config = config.lines()
            .filter(|l| !l.contains("#cmakedefine"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(build.join("libssh2_config.h"), &config).unwrap();
        cfg.include(&build);
    }

    cfg.define("LIBSSH2_HAVE_ZLIB", None);
    if let Some(path) = env::var_os("DEP_Z_INCLUDE") {
        cfg.include(path);
    }

    if let Some(path) = env::var_os("DEP_OPENSSL_INCLUDE") {
        if let Some(path) = env::split_paths(&path).next() {
            if let Some(path) = path.to_str() {
                if path.len() > 0 {
                    cfg.include(path);
                }
            }
        }
    }

    let libssh2h = fs::read_to_string("libssh2/include/libssh2.h").unwrap();
    let version_line = libssh2h.lines()
        .find(|l| l.contains("LIBSSH2_VERSION"))
        .unwrap();
    let version = &version_line[version_line.find('"').unwrap() + 1..version_line.len() - 1];

    let pkgconfig = dst.join("lib/pkgconfig");
    fs::create_dir_all(&pkgconfig).unwrap();
    fs::write(
        pkgconfig.join("libssh2.pc"),
        fs::read_to_string("libssh2/libssh2.pc.in")
            .unwrap()
            .replace("@prefix@", dst.to_str().unwrap())
            .replace("@exec_prefix@", "")
            .replace("@libdir@", dst.join("lib").to_str().unwrap())
            .replace("@includedir@", include.to_str().unwrap())
            .replace("@LIBS@", "")
            .replace("@LIBSREQUIRED@", "")
            .replace("@LIBSSH2VER@", version),
    ).unwrap();

    cfg.warnings(false);
    cfg.compile("ssh2");

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=user32");
    }
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
