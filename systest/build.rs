extern crate ctest2;

use std::env;

fn main() {
    let mut cfg = ctest2::TestGenerator::new();
    cfg.header("libssh2.h")
        .header("libssh2_publickey.h")
        .header("libssh2_sftp.h")
        .include(env::var("DEP_SSH2_INCLUDE").unwrap())
        .type_name(|s, is_struct, _is_union| {
            if s == "stat" {
                // Ensure that we emit `struct stat` rather than just a `stat` typedef.
                format!("struct stat")
            } else if s == "libssh2_struct_stat" {
                // libssh2_struct_stat is a typedef so ensure that we don't emit
                // `struct libssh2_struct_stat` in the C code we generate
                s.to_string()
            } else if is_struct && !s.starts_with("LIB") {
                // Otherwise we prefer to emit `struct foo` unless the type is `LIB_XXX`
                format!("struct {}", s)
            } else {
                // All other cases: just emit the type name
                s.to_string()
            }
        })
        .skip_type(|t| t.ends_with("FUNC") || t.contains("KBDINT"))
        .skip_fn(|f| {
            f == "libssh2_userauth_password_ex"
                || f == "libssh2_session_init_ex"
                || f == "libssh2_userauth_keyboard_interactive_ex"
        });
    cfg.generate("../libssh2-sys/lib.rs", "all.rs");
}
