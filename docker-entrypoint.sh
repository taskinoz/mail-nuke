#!/bin/sh
set -eu

# Bind mounts keep the host directory's ownership instead of the ownership baked
# into the image. Repair it once when needed, then run the application without
# root privileges.
if ! setpriv --reuid=10001 --regid=10001 --init-groups test -w /data; then
    chown -R 10001:10001 /data
fi

exec setpriv --reuid=10001 --regid=10001 --init-groups "$@"
