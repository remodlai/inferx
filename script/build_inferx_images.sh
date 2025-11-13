#!/usr/bin/env bash

# Build InferX binaries and Docker images inside Ubuntu 22.04 via Docker.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UBUNTU_IMAGE="${UBUNTU_IMAGE:-ubuntu:22.04}"
VERSION="${VERSION:-$(cd "$ROOT_DIR" && git rev-parse --abbrev-ref HEAD)}"

if [[ -z "${DOCKERHUB_USERNAME:-}" || -z "${DOCKERHUB_PASSWORD:-}" ]]; then
  echo "ERROR: DOCKERHUB_USERNAME and DOCKERHUB_PASSWORD must be set." >&2
  exit 1
fi

docker run --rm \
  -v "$ROOT_DIR":/workspace \
  -w /workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e VERSION="$VERSION" \
  -e DOCKERHUB_USERNAME \
  -e DOCKERHUB_PASSWORD \
  "$UBUNTU_IMAGE" \
  bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      gnupg software-properties-common tzdata build-essential pkg-config \
      libssl-dev protobuf-compiler curl docker.io git ca-certificates
    add-apt-repository ppa:deadsnakes/ppa -y >/dev/null
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      python3.12 python3.12-dev python3.12-venv
    dpkg-reconfigure -f noninteractive tzdata >/dev/null

    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
    update-alternatives --set python3 /usr/bin/python3.12
    update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1
    update-alternatives --set python /usr/bin/python3.12

    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | \
      sh -s -- -y --default-toolchain stable
    . "$HOME/.cargo/env"

    echo ">>> Building svc binary"
    cargo +stable build --bin svc

    echo ">>> Building ixctl binary"
    OPENSSL_STATIC=1 cargo +stable build --bin ixctl

    echo ">>> Preparing Docker build context"
    mkdir -p ./target/svc/inferx/config
    cp ./target/debug/svc ./target/svc/
    cp ./deployment/svc.Dockerfile ./target/svc/Dockerfile
    cp nodeconfig/node*.json ./target/svc/inferx/config/ || echo "No node config"
    cp ./deployment/svc-entrypoint.sh ./target/svc/svc-entrypoint.sh
    cp onenode_logging_config.yaml ./target/svc/ || echo "No logging config"

    echo ">>> Building Docker image remodlai/inferx_platform:${VERSION}"
    docker build --build-arg UBUNTU_VERSION=22.04 \
      -f ./target/svc/Dockerfile \
      -t remodlai/inferx_platform:${VERSION} ./target/svc
    docker tag remodlai/inferx_platform:${VERSION} remodlai/inferx_na:${VERSION}

    echo ">>> Logging into Docker Hub"
    printf "%s" "$DOCKERHUB_PASSWORD" | \
      docker login -u "$DOCKERHUB_USERNAME" --password-stdin

    echo ">>> Pushing images"
    docker push remodlai/inferx_platform:${VERSION}
    docker push remodlai/inferx_na:${VERSION}

    echo "✅ Local build complete for ${VERSION}"
  '
