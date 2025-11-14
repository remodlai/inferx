#!/bin/bash
set -e

if [ "${ENABLE_COREDUMP}" = "true" ]; then
  echo "Enable coredump"
  ulimit -c unlimited
  echo "/var/log/inferx/core.na.%e.%p" > /proc/sys/kernel/core_pattern
else
  echo "Disable coredump"
  ulimit -c 0
fi

# Run the InferX runtime (NodeAgent/IxProxy from tarball)
exec /opt/inferx/bin/inferx "$@"
