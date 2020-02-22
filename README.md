# ssh2-rs

[![Build Status](https://travis-ci.com/alexcrichton/ssh2-rs.svg?branch=master)](https://travis-ci.com/alexcrichton/ssh2-rs)
[![Build Status](https://github.com/alexcrichton/ssh2-rs/workflows/linux/badge.svg)](https://github.com/alexcrichton/ssh2-rs/actions?workflow=linux)
[![Build Status](https://github.com/alexcrichton/ssh2-rs/workflows/Windows/badge.svg)](https://github.com/alexcrichton/ssh2-rs/actions?workflow=Windows)
[![Build Status](https://github.com/alexcrichton/ssh2-rs/workflows/macOS/badge.svg)](https://github.com/alexcrichton/ssh2-rs/actions?workflow=macOS)

[Documentation](https://docs.rs/ssh2)

Rust bindings to libssh2, an ssh client library.

## Usage

```toml
# Cargo.toml
[dependencies]
ssh2 = "0.8"
```

## Building on OSX 10.10+

This library depends on OpenSSL. To get OpenSSL working follow the
[`openssl` crate's instructions](https://github.com/sfackler/rust-openssl#macos).

Starting with version `0.4` of `ssh2`, you can enable the `vendored-openssl` feature
to have `libssh2` built against a statically built version of openssl as [described
here](https://docs.rs/openssl/0.10.24/openssl/#vendored)

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
