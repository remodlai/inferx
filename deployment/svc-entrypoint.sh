# #!/bin/bash
# set -e

# if [ "${ENABLE_COREDUMP}" = "true" ]; then
#   echo "Enable coredump"
#   # allow unlimited core file size
#   ulimit -c unlimited
#   # set core dump file location & naming
#   echo "/opt/inferx/log/core.na.%e.%p" > /proc/sys/kernel/core_pattern
# else
#   echo "Disable coredump"
#   # disallow core dumps
#   ulimit -c 0
# fi

# ./svc "$@"

#!/bin/bash
set -e

if [ "${ENABLE_COREDUMP}" = "true" ]; then
  echo "Enable coredump"
  ulimit -c unlimited
  echo "/opt/inferx/log/core.na.%e.%p" > /proc/sys/kernel/core_pattern
else
  echo "Disable coredump"
  ulimit -c 0
fi

BIN_DIR="/opt/inferx/bin"
cd "$BIN_DIR"

if [ -x "./svc" ]; then
  CMD="./svc"
elif [ -x "./inferx" ]; then
  CMD="./inferx"
else
  echo "ERROR: no svc or inferx binary found in ${BIN_DIR}" >&2
  ls -al "$BIN_DIR"
  exit 1
fi

exec "$CMD" "$@"
