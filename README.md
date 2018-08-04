# ssh2-rs

[![Build Status](https://travis-ci.org/alexcrichton/ssh2-rs.svg?branch=master)](https://travis-ci.org/alexcrichton/ssh2-rs)
[![Build Status](https://ci.appveyor.com/api/projects/status/dwc9c26tfdpg52on?svg=true)](https://ci.appveyor.com/project/alexcrichton/ssh2-rs)

[Documentation](https://docs.rs/ssh2)

Rust bindings to libssh2

## Usage

Ensure that [`zlib`](https://zlib.net/) is installed (Debian: `sudo apt-get
install zlib1g-dev`, OSX: `brew install zlib-devel`,
[Windows](http://gnuwin32.sourceforge.net/packages/zlib.htm))

```toml
# Cargo.toml
[dependencies]
ssh2 = "0.3"
```

## Building on OSX 10.10+

Currently libssh2 requires linking against OpenSSL, and to compile libssh2 it
also needs to find the OpenSSL headers. On OSX 10.10+ the OpenSSL headers have
been removed, but if you're using Homebrew you can install them via:

```sh
brew install openssl
```

This crate also needs to have `cmake` installed:

```sh
brew install cmake
```
