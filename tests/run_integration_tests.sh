#!/bin/bash
set -e

# This script spawns an ssh daemon with a known configuration so that we can
# test various functionality against it.

# Tell the tests to use the port number we're using to spawn this server
export RUST_SSH2_FIXTURE_PORT=8022

cleanup() {
  # Stop the ssh server
  kill $(< $SSHDIR/sshd.pid)
  # Stop local ssh agent
  kill $SSH_AGENT_PID
}
trap cleanup EXIT

# Blow away any prior state and re-configure our test server
SSHDIR=$(pwd)/tests/sshd

rm -rf $SSHDIR
mkdir -p $SSHDIR

eval $(ssh-agent -s)

ssh-keygen -t rsa -f $SSHDIR/id_rsa -N "" -q
chmod 0600 $SSHDIR/id_rsa*
ssh-add $SSHDIR/id_rsa
cp $SSHDIR/id_rsa.pub $SSHDIR/authorized_keys

ssh-keygen -f $SSHDIR/ssh_host_rsa_key -N '' -t rsa

cat > $SSHDIR/sshd_config <<-EOT
AuthorizedKeysFile=$SSHDIR/authorized_keys
HostKey=$SSHDIR/ssh_host_rsa_key
PidFile=$SSHDIR/sshd.pid
Subsystem sftp /usr/libexec/sftp-server
UsePAM yes
X11Forwarding yes
PrintMotd yes
PermitTunnel yes
AllowTcpForwarding yes
MaxStartups 500
EOT

# Start an ssh server
/usr/sbin/sshd -p $RUST_SSH2_FIXTURE_PORT -f $SSHDIR/sshd_config -E /dev/stderr &
# Give it a moment to start up
sleep 2

# Run the tests against it
RUST_BACKTRACE=1 cargo test --all
