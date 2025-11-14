#!/bin/bash
set -euo pipefail

LOG_DIR="/var/log/inferx"
K3S_LOG_FILE="/var/log/k3s-agent.log"
AGENT_LOG_FILE="${LOG_DIR}/inferx-agent.log"

mkdir -p "${LOG_DIR}"
touch "${AGENT_LOG_FILE}"

if [ -n "${K3S_URL:-}" ] && [ -n "${K3S_TOKEN:-}" ]; then
  export INSTALL_K3S_SKIP_ENABLE=true
  export INSTALL_K3S_SKIP_START=true
  /usr/local/bin/install-k3s.sh

  AGENT_ARGS="--server ${K3S_URL} --token ${K3S_TOKEN}"
  if [ -n "${K3S_NODE_NAME:-}" ]; then
    AGENT_ARGS="${AGENT_ARGS} --node-name ${K3S_NODE_NAME}"
  fi
  if [ -n "${INSTALL_K3S_EXEC:-}" ]; then
    AGENT_ARGS="${AGENT_ARGS} ${INSTALL_K3S_EXEC}"
  fi

  echo "[+] Launching k3s agent with args: ${AGENT_ARGS}"
  nohup /usr/local/bin/k3s agent ${AGENT_ARGS} >"${K3S_LOG_FILE}" 2>&1 &
fi

export RUST_BACKTRACE="${RUST_BACKTRACE:-full}"

set +e
/usr/local/bin/inferx-agent-entrypoint.sh "$@" 2>&1 | tee -a "${AGENT_LOG_FILE}"
AGENT_RC=${PIPESTATUS[0]}
set -e

if [ "${AGENT_RC}" -ne 0 ]; then
  echo "InferX agent exited with ${AGENT_RC}, dumping log ${AGENT_LOG_FILE}:"
  cat "${AGENT_LOG_FILE}"
  echo "Container will stay alive for debugging. Press Ctrl+C or stop the pod when done."
  tail -f /dev/null
fi

exit "${AGENT_RC}"
