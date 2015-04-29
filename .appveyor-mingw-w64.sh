#!/bin/sh
set -e
cd `dirname "$0"`

# We need to test this library with mingw-w64 as it requires libcrypt on windows
# which is apparently not available in the normal MinGW distribution
f=x86_64-4.9.2-release-win32-seh-rt_v3-rev1.7z
url=http://sourceforge.net/projects/mingw-w64/files
url=$url/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/4.9.2
url=$url/threads-win32/seh/$f
if ! [ -e $f ]; then
    curl -LsSO $url
fi
7z x $f > /dev/null
mv mingw64 /MinGW
export PATH=/MinGW/bin:$PATH

# Now that everything is in place let's build/test. Unfortunately now, though,
# the tests require an SSH server to play around with which isn't available on
# appveyor, so just build them, don't run them.
cargo build --verbose
cargo test --verbose --no-run
