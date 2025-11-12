# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

InferX is a serverless AI inference platform written in Rust with Python components. It enables ultra-fast cold starts (<2 seconds for 22B+ models) through GPU snapshotting technology, achieving 80-90% GPU utilization via high deployment density and lambda-like auto-scaling.

## Architecture

The platform consists of four main components running as microservices:

1. **Gateway** (`ixshare/src/gateway/`) - OpenAI-compatible REST API gateway for inference requests
2. **Scheduler** (`ixshare/src/scheduler/`) - Cluster-level scheduler that manages instance assignment and cold starts
3. **State Service** (`ixshare/src/state_svc/`) - Distributed state management backed by etcd
4. **Dashboard** (`dashboard/`) - Flask-based web UI for platform management

The main service binary (`svc`) can run all components together or individually based on the `RUN_SERVICE` environment variable (options: `StateSvc`, `Scheduler`, `Gateway`, `All`).

## Build Commands

### Core Platform
```bash
# Build main service (Gateway, Scheduler, StateSvc)
make svc

# Build CLI tool
make ctl

# Build dashboard
make dash

# Build model runtime container
make runmodel

# Build all core components
make all
```

### Docker Images
```bash
# Build platform service container
make svcdeploy

# Build and push all components
make pushall

# Build specific images
make pushdash    # Dashboard only
make pushsvc     # Platform service only
make pushdb      # PostgreSQL with schema
make pushspdk    # SPDK blobstore containers
```

### Testing
```bash
# Run load tests with hey/ab
cd test && ./test.sh

# Build test tools
cd test/ixtest && cargo build
```

## Running the Platform

### Docker Compose (Single Node)
```bash
# Standard deployment
make run

# With blobstore enabled
make runblob

# Stop services
make stop         # Standard
make stopblob     # Blobstore
```

### Kubernetes
```bash
# Deploy all services
make runkblob

# Deploy individual components
make rungateway
make runscheduler
make runstatesvc
make runkdash
make runna        # Node agent

# Stop components
make stopgateway
make stopscheduler
make stopall      # Everything
```

## Development Workflow

### Code Organization
- `svc/` - Main service entry point (single binary for all services)
- `ixctl/` - CLI client for managing models and packages
- `ixshare/` - Shared libraries containing all service logic
- `inferxlib/` - Common utilities and types
- `dashboard/` - Python Flask web application
- `config/` - Model and policy configuration JSON files
- `nodeconfig/` - Node resource and networking configuration
- `deployment/` - Dockerfiles and deployment scripts
- `k8s/` - Kubernetes manifests

### Configuration

**Node Config** (`nodeconfig/node*.json`):
- `nodeName`, `etcdAddrs`, `stateSvcAddrs` - Service discovery
- `resources.GPUs` - Set to `"Auto"` for auto-detection or specify count
- `resources.GPUType` - GPU model identifier (e.g., `"A4000"`)
- `snapshotDir` - Path for GPU state snapshots
- `enableBlobStore` - Use SPDK blobstore for snapshot storage

**Model Config** (`config/*.json`):
- `type: "funcpolicy"` - Defines scaling policies (min/max replicas, queue behavior)
- `type: "tenant"` - Tenant isolation configuration

### Environment Variables

**ixctl CLI**:
- `INFX_GATEWAY_URL` - Gateway URL (default: localhost:4000)
- `IFERX_APIKEY` - API key authentication
- `IFERX_SECRET`, `IFERX_USERNAME`, `IFERX_PASSWORD` - OAuth2 credentials

**Service Runtime**:
- `RUN_SERVICE` - Service mode: `All`, `StateSvc`, `Scheduler`, or `Gateway`
- `ETCD_ADDR` - etcd connection string
- `STATESVC_ADDR` - State service URL
- `AUDITDB_ADDR` - PostgreSQL connection for audit logs
- `SECRDB_ADDR` - PostgreSQL connection for secrets
- `INFERX_ADMIN_APIKEY` - Admin API key
- `NODE_NAME`, `POD_IP` - Node identification

## API Endpoints

Gateway exposes OpenAI-compatible endpoints at `http://localhost:4000`:
```
POST /funccall/{tenant}/{model_name}/v1/completions
POST /funccall/{tenant}/{model_name}/v1/chat/completions
```

Dashboard runs on port 443 (HTTPS) with Keycloak authentication.

## Key Technologies

- **Rust**: tokio async runtime, tonic gRPC, axum HTTP server
- **Python**: Flask, gunicorn, PostgreSQL via psycopg2
- **Storage**: etcd (metadata), PostgreSQL (audit/secrets), SPDK (optional blobstore)
- **Auth**: Keycloak OAuth2/OIDC
- **Observability**: Jaeger tracing, Prometheus metrics

## Notes

- The platform requires privileged containers and host networking for GPU snapshotting
- Snapshots are stored in `/opt/inferx/snapshot` by default
- Logs go to `/opt/inferx/log/`
- The main Rust binary is multi-threaded (16 worker threads) using tokio
- All services communicate via gRPC except the Gateway which uses HTTP/REST
- Model deployment uses vLLM runtime containers with OpenAI compatibility
