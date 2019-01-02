# ssh2-rs

[![Build Status](https://travis-ci.com/alexcrichton/ssh2-rs.svg?branch=master)](https://travis-ci.com/alexcrichton/ssh2-rs)
[![Build Status](https://ci.appveyor.com/api/projects/status/dwc9c26tfdpg52on?svg=true)](https://ci.appveyor.com/project/alexcrichton/ssh2-rs)

[Documentation](https://docs.rs/ssh2)

Rust bindings to libssh2

## Usage

```toml
# Cargo.toml
[dependencies]
ssh2 = "0.3"
```

## Building on OSX 10.10+

This library depends on OpenSSL. To get OpenSSL working follow the
[`openssl` crate's instructions](https://github.com/sfackler/rust-openssl#macos).
