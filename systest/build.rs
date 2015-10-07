extern crate ctest;

use std::env;

fn main() {
    let mut cfg = ctest::TestGenerator::new();
    cfg.header("libssh2.h")
       .header("libssh2_publickey.h")
       .header("libssh2_sftp.h")
       .include(env::var("DEP_SSH2_INCLUDE").unwrap())
       .type_name(|s, is_struct| {
           if (is_struct || s == "stat") && !s.starts_with("LIB") {
               format!("struct {}", s)
           } else {
               s.to_string()
           }
        })
        .skip_type(|t| t.ends_with("FUNC"))
        .skip_fn(|f| {
            f == "libssh2_userauth_password_ex" ||
                f == "libssh2_session_init_ex"
        });
    cfg.generate("../libssh2-sys/lib.rs", "all.rs");
}
