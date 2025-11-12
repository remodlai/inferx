# InferX Rust Codebase - Technical Architecture Summary

## 1. System Architecture Overview

InferX is a serverless GPU-based inference platform that achieves 2-second cold starts and 80%+ GPU utilization through intelligent snapshot-based container management and scheduling.

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     InferX Platform                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ API Gateway      │  │ Scheduler    │  │ State Service   │  │
│  │ (Port 4000)      │  │ (Port 1238)  │  │ (Port 1237)     │  │
│  │ - Route requests │  │ - Alloc GPUs │  │ - etcd client   │  │
│  │ - Auth/logging   │  │ - Pod lease  │  │ - Watch events  │  │
│  └──────────────────┘  └──────────────┘  └─────────────────┘  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ etcd (Metadata Store) - Port 2379                       │   │
│  │ - Stores Nodes, Functions, Pods, Snapshots, Policies    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Per Node (K8s DaemonSet):                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Node Agent (NodeAgent) - Privileged Container           │   │
│  │ - Creates worker pod containers (Docker-in-K8s)         │   │
│  │ - Manages GPU allocation (NVIDIA_VISIBLE_DEVICES)       │   │
│  │ - Snapshots/restores container state (CPU + GPU)        │   │
│  │ - Communicates with Scheduler via gRPC                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Service Implementation Details

### 2.1 API Gateway (`ixshare/src/gateway/`)

**File: `http_gateway.rs` (1,686 lines)**
- Main HTTP server using Axum framework
- Handles `/funccall` endpoints for inference requests
- Routes: GET `/`, health checks, function invocations
- Integration points:
  - `GwObjRepo` - manages cached objects (Functions, Pods, Nodes)
  - `FuncAgentMgr` - manages function agent lifecycle
  - `FuncWorker` - handles HTTP connections to worker pods
  - `SCHEDULER_CLIENT` - requests worker leases
  - `SqlAudit` - logs requests to PostgreSQL

**File: `func_agent_mgr.rs` (893 lines)**
- Manages agent per function (tenant/namespace/function_name)
- Responsibilities:
  - Pooling of workers (`FuncWorker` instances)
  - Keepalive management for idle connections
  - Scaling policy enforcement (via `FuncPolicy`)
  - Status tracking (Init, Ready, Idle, Working)

**File: `func_worker.rs` (1,056 lines)**
- Represents a single containerized worker instance
- Connection pooling to worker containers (HTTP via port 80)
- Parallel request handling (`parallelLevel` = max concurrent requests)
- Keepalive worker lifecycle:
  - When keepalive=true: connection persists across requests
  - When keepalive=false: connection closed after request
- Performance tracking: connection time, queue time, process time

**File: `gw_obj_repo.rs` (968 lines)**
- Maintains local cache of all cluster objects:
  - **Nodes** - cluster compute resources
  - **Functions** - function definitions
  - **Pods** - deployed function instances (state = Ready, Standby, Resuming)
  - **Snapshots** - saved container states
  - **Policies** - scaling rules
- Uses `InformerFactory` to watch etcd for changes
- Propagates updates to scheduler via `RefreshGateway` call

### 2.2 Scheduler (`ixshare/src/scheduler/`)

**File: `scheduler.rs` (614 lines)**
- Core orchestration engine
- Event processing from delta events (added/updated/deleted objects)
- Two-channel architecture:
  - `eventRx`: Receives delta events from etcd watches
  - `msgRx`: Receives messages (LeaseWorker, ReturnWorker, ConnectScheduler)
- Main service: `SchedulerSvc()` spawns:
  - `SchedulerProcess()` - gRPC server + etcd registration
  - `SCHEDULER.StartProcess()` - event handler loop

**File: `scheduler_handler.rs` (2,976 lines - **LARGEST**)

Core scheduling logic:

```rust
struct SchedulerHandler {
    nodes: BTreeMap<NodeName, NodeStatus>,          // All nodes with resources
    workerPods: BTreeMap<String, WorkerPod>,        // All deployed pods
    funcPolicies: BTreeMap<String, FuncPolicy>,     // Scaling policies
    snapshotScheduleIndex: BiIndex<SnapshotScheduleInfo>,
    // ... snapshot management
}
```

**LeaseWorker Flow** (request processing):
1. **Request arrives**: `LeaseWorkerReq` from gateway
   - Contains: `tenant`, `namespace`, `funcname`, `fprevision`, `gateway_id`
2. **Find existing pod**: Search idle pods matching function
3. **If found**: 
   - Transition pod from Idle → Working(gateway_id)
   - Return pod IP + port in `LeaseWorkerResp`
   - Establish connection (gateway.funcWorker communicates directly with pod)
4. **If not found**:
   - **Allocate resources** from NodeStatus.available
   - **Select node** based on resource fit
   - **Create pending pod**: scheduled for deployment
   - **Node Agent creates container**: via `CreateFuncPodReq` gRPC
   - Return pod details once container is Ready

**ReturnWorker Flow**:
1. **Request arrives**: `ReturnWorkerReq` with pod ID
2. **Transition pod**: Working(gw_id) → Idle
3. **Track failure**: if `failworker=true`, mark pod for replacement

**Resource Management**:
```rust
struct NodeResources {
    cpu: i64,
    mem: i64,
    gpus: HashMap<GPUType, GPUResources>,  // GPU vendor + available slots
    gpuContextCount: i64,
}

struct GPUResources {
    total: i64,
    available: i64,
    vRam: i64,  // VRAM per GPU in MB
}
```

**GPU Allocation**:
- Fractional GPU slicing: `GPU.Count=1, vRam=14200` allocates 1/X of a GPU
- Context overhead tracking: memory required per GPU context
- Allocation strategy:
  1. Check if node has available GPU slots
  2. Allocate vRam quota from GPU.vRam pool
  3. Deduct context overhead from available GPU memory

**Snapshot Scheduling**:
- `SnapshotTask` queue: schedules container snapshots on nodes
- State tracking: `Init → Scheduled → Done` or `ScheduleFail`
- Audit logging: tracks all snapshot operations

**File: `scheduler_register.rs`**
- Registers scheduler in etcd as service discoverable
- Maintains lease for keepalive heartbeat

**File: `sched_obj_repo.rs`**
- Watches etcd for object changes
- Updates scheduler's local cache
- Triggers event handlers

### 2.3 State Service (`ixshare/src/state_svc/`)

**File: `state_svc.rs` (708 lines)**
- Central metadata repository interface to etcd
- Manages object managers:
  - `FuncMgr` - function definitions
  - `TenantMgr` - tenant isolation
  - `NamespaceMgr` - namespace grouping
- Watches etcd keys:
  - `Tenant::KEY`
  - `Namespace::KEY`
  - `Function::KEY`
  - `Node::KEY`
  - `FuncPolicy::KEY`
  - `SchedulerInfo::KEY`
- Listens to PostgreSQL audit database for triggers

**File: `state_svc.rs` - `ProcessDeltaEvent()`**
```rust
match event.type_ {
    EventType::Added => {
        // Route to appropriate manager based on obj.objType
        match obj.objType {
            Tenant::KEY => tenantMgr.AddObject(...),
            Namespace::KEY => namespaceMgr.AddObject(...),
            Function::KEY => funcMgr.AddObject(...),
            _ => {}
        }
    }
    EventType::Modified => { /* update managers */ }
    EventType::Deleted => { /* remove from managers */ }
}
```

### 2.4 etcd Integration (`ixshare/src/etcd/`)

**File: `etcd_store.rs` (731 lines)**
- Async Rust wrapper around etcd_client
- Implements `BackendStore` trait for cache layer
- Key operations:
  - `Get(key, minRevision)` - fetch with consistency check
  - `List(prefix, options)` - range queries with pagination
  - `Watch(key)` - streaming updates
  - `Txn()` - atomic operations

**Storage Structure**:
```
/registry/
  /tenant/
    {tenant-name}/...
  /namespace/
    {tenant}/{namespace}/...
  /function/
    {tenant}/{namespace}/{function-name}
  /pod/
    {tenant}/{namespace}/{function-name}/{pod-id}
  /snapshot/
    {tenant}/{namespace}/{function-name}/{snapshot-id}
  /node/
    {node-name}
```

**Watch Implementation** (`watch.rs`):
- Creates persistent watch stream from etcd
- Handles reconnection on disconnect
- Converts etcd KeyValue changes to `DeltaEvent` objects
- Supports filtering by prefix/range

---

## 3. Container Management

### 3.1 Pod Lifecycle

**States**: `Init → Resuming → Ready → (Idle ↔ Working) → Terminating`

**State Transitions**:
- **Init**: Pod object created in etcd
- **Resuming**: Node Agent is restoring from snapshot
- **Ready**: Pod can receive requests (initial state)
- **Idle**: Pod is ready but not processing
- **Working(gateway_id)**: Processing request from specific gateway
- **Terminating**: Being shut down

### 3.2 Container Creation Flow

**1. Scheduler allocates resources & creates PendingPod**
```
SchedulerHandler.AllocResource(nodeStatus, request_resources)
  → NodeStatus.available.Alloc()
  → Returns NodeResources for this pod
  → Creates PendingPod(nodeName, podKey, funcId, resources)
```

**2. Node Agent receives CreateFuncPodReq**

gRPC message from Scheduler → Node Agent (port varies per component):
```protobuf
message CreateFuncPodReq {
  string tenant = 1;
  string namespace = 2;
  string funcname = 3;
  int64  fprevision = 4;
  string id = 5;                    // Pod ID
  repeated KV labels = 6;
  repeated KV annotations = 7;
  CreatePodType create_type = 8;    // Normal, Snapshot, Restore
  string funcspec = 9;              // JSON function config
  string alloc_resources = 10;      // Allocated resources JSON
  string resource_quota = 11;       // Available quota
  repeated TerminatePodReq terminate_pods = 12;  // Pods to kill for space
}
```

**3. Node Agent spawns container**

Node Agent implementation (not in ixshare, external Rust service):
```bash
# Container creation sequence:
docker create \
  --name {pod-id} \
  --cpus={cpu_count} \
  --memory={mem_mb}m \
  --gpus='"device={gpu_indices}"' \  # NVIDIA_VISIBLE_DEVICES
  -e "CUDA_VISIBLE_DEVICES=0,1,2" \
  -p 80:{container_port} \
  {image}

docker start {pod-id}
```

**GPU allocation** via environment variables:
```bash
NVIDIA_VISIBLE_DEVICES=0        # For 1/3 GPU slice on GPU 0
NVIDIA_VISIBLE_DEVICES=0,1      # For 2 full GPUs
```

**4. Pod starts and becomes Ready**

- Container initialization: pulls image, loads model
- Health probe: `/health` endpoint checks readiness
- Pod event: `NodeAgentStreamMsg.PodEvent(Add, pod_json)` → State Service
- Scheduler receives update via informer: Pod.status.state=Ready

**5. Transition to Idle**
```rust
// scheduler/scheduler_handler.rs
if pod.status.state == PodState::Ready {
    WorkerPod::SetIdle(SetIdleSource::New)
}
```

### 3.3 Snapshot and Restore

**Snapshot Creation**:
1. Pod is running and initialized
2. Scheduler sends snapshot request to Node Agent
3. Node Agent:
   - Pauses container (CRIU - Container Runtime Interface for User-space)
   - Copies CPU state to disk
   - Snapshots GPU memory to disk (via NVIDIA CUDA APIs)
   - Creates `FuncSnapshot` object in etcd
4. Pod wakes up and continues running

**Snapshot Restore**:
- New pod requested with `create_type=Restore`
- Node Agent:
  - Restores CPU state from snapshot
  - Restores GPU state to GPU memory
  - Container resumes execution (warm start)
  - Pod becomes Ready in ~0.5-2 seconds

---

## 4. Communication Protocols

### 4.1 gRPC Services

**SchedulerService** (Scheduler listening):
```protobuf
service SchedulerService {
  rpc ConnectScheduler(ConnectReq) returns (ConnectResp);  // Node Agent registration
  rpc LeaseWorker(LeaseWorkerReq) returns (LeaseWorkerResp);      // Get idle pod
  rpc ReturnWorker(ReturnWorkerReq) returns (ReturnWorkerResp);   // Return pod
  rpc RefreshGateway(RefreshGatewayReq) returns (RefreshGatewayResp);
}
```

**NodeAgentService** (Node Agent listening):
```protobuf
service NodeAgentService {
  rpc CreateFuncPod(CreateFuncPodReq) returns (CreateFuncPodResp);
  rpc TerminatePod(TerminatePodReq) returns (TerminatePodResp);
  rpc ResumePod(ResumePodReq) returns (ResumePodResp);  // From standby
  rpc ReadPodLog(ReadPodLogReq) returns (ReadPodLogResp);
  rpc RemoveSnapshot(RemoveSnapshotReq) returns (RemoveSnapshotResp);
}
```

**IxMetaService** (State Service listening):
```protobuf
service IxMetaService {
  rpc Get(GetRequestMessage) returns (GetResponseMessage);
  rpc List(ListRequestMessage) returns (ListResponseMessage);
  rpc Watch(WatchRequestMessage) returns (stream WEvent);
  rpc Create(CreateRequestMessage) returns (CreateResponseMessage);
  rpc Update(UpdateRequestMessage) returns (UpdateResponseMessage);
  rpc Delete(DeleteRequestMessage) returns (DeleteResponseMessage);
}
```

### 4.2 Request Flow: Client → Inference Response

```
User Request (HTTP/REST)
  ↓
Gateway.http_gateway:4000
  ├─ Parse /funccall POST request
  ├─ Extract: tenant, namespace, funcname, payload
  ├─ Auth check via KeyCloakConfig
  ├─ Look up Function in GwObjRepo cache
  ├─ Check FuncPolicy for scaling rules
  ├─ Call Scheduler.LeaseWorker(funcname, fprevision)
  │
  └─ Scheduler.scheduler_handler
      ├─ Search idle pods for this function
      ├─ If found: return LeaseWorkerResp(pod_ip, pod_port)
      ├─ If not:
      │   ├─ Allocate resources from node
      │   ├─ Create pod via Node Agent.CreateFuncPod()
      │   ├─ Wait for pod Ready state
      │   └─ Return LeaseWorkerResp(pod_ip, pod_port)
  
  Gateway.func_worker (reuses connection if keepalive)
    └─ HTTP request to pod:80/funccall
         ↓
    Pod (vLLM/TensorRT/custom model server)
      └─ /funccall POST handler
           ↓
         Inference execution
           ↓
         HTTP response (JSON)
           ↓
    Gateway receives response
      └─ Return to user

  Gateway.scheduler.ReturnWorker(pod_id)
    └─ Scheduler transitions pod: Working → Idle
```

---

## 5. Configuration System

### 5.1 Function Configuration

**File: `config/Qwen2.5-7B-Instruct-GPTQ-Int8.json`**

```json
{
  "type": "function",
  "tenant": "public",
  "namespace": "Qwen",
  "name": "Qwen2.5-7B-Instruct-GPTQ-Int8",
  "object": {
    "spec": {
      "image": "vllm/vllm-openai:v0.9.0",
      "commands": [
        "--model", "Qwen/Qwen2.5-7B-Instruct-GPTQ-Int8",
        "--gpu-memory-utilization", "0.95",
        "--max-model-len", "500"
      ],
      "resources": {
        "CPU": 20000,           // millicores
        "Mem": 30000,           // MB
        "GPU": {
          "Type": "Any",        // or "H100", "A100", etc.
          "Count": 1,           // number of GPUs
          "vRam": 14200         // VRAM per GPU in MB
        }
      },
      "envs": [
        ["LD_LIBRARY_PATH", "/usr/local/lib/python3.12/dist-packages/nvidia/cuda_nvrtc/lib/:$LD_LIBRARY_PATH"],
        ["VLLM_CUDART_SO_PATH", "/usr/local/cuda-12.1/targets/x86_64-linux/lib/libcudart.so.12"]
      ],
      "mounts": [
        {
          "hostpath": "/opt/inferx/cache",
          "mountpath": "/root/.cache/huggingface"
        }
      ],
      "endpoint": {
        "port": 8000,
        "schema": "Http",
        "probe": "/health"
      },
      "sample_query": {
        "apiType": "text2text",
        "prompt": "Give me a short introduction to large language model.",
        "path": "v1/completions",
        "body": { /* OpenAI API payload */ }
      },
      "standby": {
        "gpu": "Mem",        // Preload snapshot to GPU memory
        "pageable": "File",  // Pageable memory stored in file
        "pinned": "File"     // Pinned memory stored in file
      },
      "policy": {
        "Link": {
          "objType": "funcpolicy",
          "namespace": "system",
          "name": "default_funcpolicy2"
        }
      }
    }
  }
}
```

### 5.2 Node Configuration

**File: `nodeconfig/node.json`**

```json
{
  "nodeName": "node1",
  "etcdAddrs": ["http://etcd:2379"],
  "hostIpCidr": "192.168.0.0/16",
  "podMgrPort": 1233,
  "tsotCniPort": 1234,
  "qletStateSvcPort": 1236,
  "statSvcPort": 1237,
  "schedulerPort": 1238,
  "gatewayPort": 4000,
  "cidr": "10.1.3.0/8",
  "stateSvcAddrs": ["http://localhost:1237"],
  "auditdbAddr": "postgresql://user:pass@db:5432/auditdb",
  "resources": {
    "CPU": 30000,          // Total node CPU in millicores
    "Mem": 400000,         // Total node memory in MB
    "GPUs": "Auto",        // Auto-detect or "all", "0-3", etc.
    "ContextOverhead": 450,// MB per GPU context
    "MaxContextPerGPU": 1  // Unused in current codebase
  },
  "snapshotDir": "/opt/inferx/snapshot",
  "enableBlobStore": false,
  "sharemem": {
    "size": 20,            // GB of shared memory
    "hugepage": true
  }
}
```

### 5.3 Configuration Reading

**File: `node_config.rs` (791 lines)**

```rust
lazy_static::lazy_static! {
    pub static ref NODE_CONFIG: NodeConfig = {
        let args: Vec<String> = std::env::args().collect();
        let configPath = if args.len() == 1 {
            "/opt/inferx/config/node.json"
        } else {
            &args[1]
        };
        NodeConfig::Load(configPath).expect("can't load config")
    };
}

pub struct GatewayConfig {
    pub nodeName: String,
    pub etcdAddrs: Vec<String>,
    pub stateSvcAddrs: Vec<String>,
    pub nodeIp: String,                    // From ENV:NODE_NAME or hostIpCidr
    pub schedulerPort: u16,
    pub auditdbAddr: String,
}

pub struct SchedulerConfig {
    pub etcdAddrs: Vec<String>,
    pub nodeIp: String,
    pub schedulerPort: u16,
}
```

---

## 6. Kubernetes Manifests

### 6.1 Node Agent DaemonSet

**File: `k8s/nodeagent.yaml`**

Key aspects:
- **DaemonSet**: Runs on every node (optionally filtered by `nodeSelector`)
- **Security Context**: Privileged mode required for:
  - Docker-in-Docker (volume mount to `/var/lib/docker`)
  - Device access (GPUs, cgroups)
  - Namespace manipulation
- **Capabilities Added**:
  - `SYS_ADMIN` - for container runtime control
  - `IPC_LOCK` - for GPU memory pinning
  - `SYS_RAWIO` - for direct hardware access
- **Volume Mounts**:
  - `/var/lib/docker` - docker daemon socket access
  - `/opt/inferx/snapshot` - container snapshots
  - `/opt/inferx/work` - working directory
  - `/dev/hugepages` - huge page memory
- **Resource Requests**:
  ```yaml
  requests:
    cpu: "15"
    memory: "40Gi"
  limits:
    cpu: "20"
    memory: "100Gi"
  ```
- **Environment**:
  - `RUN_SERVICE=NodeAgent`
  - `STATESVC_ADDR=http://statesvc:1237`
  - `NODE_NAME` from field reference
  - `POD_IP` from field reference
- **Node Selector**:
  ```yaml
  nodeSelector:
    inferx_nodeType: inferx_file  # or inferx_blob
  ```

### 6.2 Scheduler Deployment

**File: `k8s/scheduler.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scheduler
spec:
  replicas: 1  # Single scheduler instance
  template:
    spec:
      hostPID: true
      containers:
      - image: inferx/inferx_platform:${VERSION}
        env:
        - name: RUN_SERVICE
          value: "Scheduler"
        - name: STATESVC_ADDR
          value: "http://statesvc:1237"
        - name: ETCD_ADDRS
          value: "http://localhost:2379"
        - name: SCHEDULER_PORT
          value: "1238"
```

### 6.3 Gateway Deployment

**File: `k8s/gateway.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
spec:
  replicas: 1  # Single gateway instance (stateless, can scale)
  template:
    spec:
      hostPID: true
      livenessProbe:
        httpGet:
          path: /
          port: 4000
        initialDelaySeconds: 10
        periodSeconds: 10
      containers:
      - image: inferx/inferx_platform:${VERSION}
        env:
        - name: RUN_SERVICE
          value: "Gateway"
        - name: INFERX_ADMIN_APIKEY
          value: "87831cdb-d07a-4dc1-9de0-fb232c9bf286"
        - name: AUDITDB_ADDR
          value: "postgresql://audit_user:123456@db:5432/auditdb"
        - name: STATESVC_ADDR
          value: "http://statesvc:1237"
        - name: ETCD_ADDRS
          value: "http://etcd:2379"
```

### 6.4 State Service Deployment

**File: `k8s/statesvc.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: statesvc
spec:
  replicas: 1
  containers:
  - image: inferx/inferx_platform:${VERSION}
    env:
    - name: RUN_SERVICE
      value: "StateSvc"
    - name: STATESVC_PORT
      value: "1237"
```

### 6.5 etcd Deployment

**File: `k8s/etcd.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: etcd
spec:
  nodeSelector:
    inferx_storage: data
  containers:
  - image: quay.io/coreos/etcd:v3.5.13
    args:
    - "--name=etcd-00"
    - "--data-dir=/opt/inferx/data/etcd"
    - "--advertise-client-urls=http://etcd-00:2379"
    - "--listen-client-urls=http://0.0.0.0:2379"
    volumeMounts:
    - name: etcd-data
      mountPath: /opt/inferx/data/etcd
  volumes:
  - name: etcd-data
    hostPath:
      path: /opt/inferx/data/etcd
      type: DirectoryOrCreate
```

---

## 7. Critical Code Paths

### 7.1 Request Processing Path

1. **HTTP Request arrives** (`gateway/http_gateway.rs`):
   ```rust
   POST /funccall with body: {tenant, namespace, funcname, payload}
   ```

2. **Gateway authenticates** (`gateway/auth_layer.rs`):
   - Validates KeyCloak token or API key
   - Extracts tenant/namespace from token or request

3. **Gateway looks up Function** (`gateway/gw_obj_repo.rs`):
   ```rust
   let func = objRepo.funcMgr.GetFunction(tenant, namespace, funcname)?;
   ```

4. **Get FuncPolicy** (`gateway/func_agent_mgr.rs`):
   ```rust
   let policy = objRepo.funcpolicyMgr.GetPolicy(&func.policyRef)?;
   // policy.maxConcurrency, .minReplicas, .maxReplicas
   ```

5. **Get or Create FuncAgent** (`gateway/func_agent_mgr.rs`):
   ```rust
   let agent = self.GetOrCreateAgent(funcId, policy)?;
   // Agent manages all workers for this function
   ```

6. **Lease Worker from Scheduler** (`gateway/func_agent_mgr.rs`):
   ```rust
   let resp = SCHEDULER_CLIENT.LeaseWorker(
       LeaseWorkerReq {
           tenant, namespace, funcname, fprevision,
           gateway_id: GatewayId()
       }
   ).await?;
   // Returns: pod_ip, pod_port, keepalive flag
   ```

7. **Scheduler Processing** (`scheduler/scheduler_handler.rs`):
   ```rust
   // Search for idle pod
   if let Some(pod) = node.pods.values()
       .find(|p| p.State() == WorkerPodState::Idle 
              && p.pod.matches(funcname, fprevision)) {
       // Transition to Working
       pod.SetWorking(gateway_id);
       return LeaseWorkerResp { error: "", ipaddr: pod_ip, ... };
   }
   
   // Otherwise allocate and create new pod
   let nodeStatus = select_best_node(&self.nodes)?;
   let allocRes = nodeStatus.AllocResource(&func.resources)?;
   
   // Create pod in etcd + notify Node Agent
   let pod = FuncPod::New(...);
   self.store.Create(pod)?;
   // Node Agent watches and creates container
   ```

8. **Worker processes request** (`gateway/func_worker.rs`):
   ```rust
   let conn = worker.connPool.getOrCreate(pod_ip:pod_port)?;
   let resp = conn.post_request(payload, timeout)?;
   ```

9. **Return worker to pool** (`scheduler/scheduler.rs`):
   ```rust
   SCHEDULER_CLIENT.ReturnWorker(ReturnWorkerReq {
       tenant, namespace, funcname, fprevision,
       id: pod_id,
       failworker: false  // or true if pod failed
   })?;
   // Scheduler: pod.SetIdle()
   ```

10. **Return response to user** (`gateway/http_gateway.rs`):
    ```rust
    Ok(Json(InferenceResponse { result: resp }))
    ```

### 7.2 Pod Allocation Algorithm

**File: `scheduler/scheduler_handler.rs - AllocatePod()`**

```rust
fn AllocatePod(
    &mut self,
    req: &LeaseWorkerReq,
) -> Result<WorkerPod> {
    // 1. Get function definition
    let func = self.funcMgr.GetFunction(
        &req.tenant, &req.namespace, &req.funcname
    )?;
    
    // 2. Get scaling policy
    let policy = self.funcpolicyMgr.GetPolicy(&func.policyRef)?;
    
    // 3. Filter nodes that can fit the function
    let feasibleNodes: Vec<_> = self.nodes.values()
        .filter(|node| {
            // Check node state
            node.state == NAState::Ready &&
            // Check resources
            node.available.CanAlloc(&func.resources)? &&
            // Check pod count limits
            node.pods.len() < policy.maxPodsPerNode
        })
        .collect();
    
    // 4. Score and select best node (binpack strategy)
    let selectedNode = feasibleNodes.iter()
        .min_by_key(|node| {
            // Pack pods densely on fewest nodes
            (node.pods.len(), -node.available.gpuMemory)
        })?;
    
    // 5. Allocate resources
    let allocRes = selectedNode.AllocResource(&func.resources)?;
    
    // 6. Create pod object
    let pod = FuncPod {
        tenant: req.tenant.clone(),
        namespace: req.namespace.clone(),
        funcname: req.funcname.clone(),
        fprevision: req.fprevision,
        id: generate_pod_id(),
        status: PodStatus {
            state: PodState::Init,
            allocResources: allocRes,
            nodeAssignment: selectedNode.node.name.clone(),
        },
    };
    
    // 7. Store pod in etcd (triggers Node Agent watch)
    self.store.Create(&pod)?;
    
    // 8. Wrap in WorkerPod (tracks gateway associations)
    let workerPod = WorkerPod::New(pod);
    self.workerPods.insert(workerPod.pod.PodKey(), workerPod.clone());
    
    return Ok(workerPod);
}
```

### 7.3 GPU Resource Tracking

**File: `scheduler/scheduler_handler.rs`**

```rust
struct GPUAllocation {
    nodeIndex: usize,      // Which node
    gpuIndex: u8,          // Which GPU on node (0-7)
    memoryAllocated: i64,  // MB allocated from this GPU
}

// Container spec generation:
fn GenerateCreatePodRequest(
    &self,
    pod: &WorkerPod,
    func: &Function,
) -> Result<CreateFuncPodReq> {
    let gpuAllocs = self.GetGPUAllocations(&pod)?;
    
    // Build NVIDIA_VISIBLE_DEVICES
    let visibleDevices = gpuAllocs.iter()
        .map(|alloc| alloc.gpuIndex.to_string())
        .collect::<Vec<_>>()
        .join(",");
    
    let mut envs = func.spec.envs.clone();
    envs.push(("NVIDIA_VISIBLE_DEVICES", visibleDevices));
    envs.push(("CUDA_VISIBLE_DEVICES", visibleDevices));
    
    Ok(CreateFuncPodReq {
        tenant: pod.pod.tenant.clone(),
        namespace: pod.pod.namespace.clone(),
        funcname: pod.pod.funcname.clone(),
        fprevision: pod.pod.fprevision,
        id: pod.pod.id.clone(),
        funcspec: serde_json::to_string(&func.spec)?,
        alloc_resources: serde_json::to_string(&pod.pod.allocResources)?,
        resource_quota: serde_json::to_string(&nodeStatus.available)?,
        create_type: CreatePodType::Normal,  // or Restore for snapshots
        // ...
    })
}
```

---

## 8. EKS Deployment Adaptations

### 8.1 Required Node Labels

```bash
# Label nodes for service placement
kubectl label nodes {node-name} inferx_nodeType=inferx_file
kubectl label nodes {node-name} inferx_storage=data  # For etcd

# Or for blob storage nodes:
kubectl label nodes {node-name} inferx_nodeType=inferx_blob
```

### 8.2 Node Agent DaemonSet Modifications for EKS

**Current Issues**:
1. Docker-in-Docker (DinD) not ideal for EKS - use containerd
2. Volume mounts assume local paths - need EBS/EFS
3. GPU device access needs AWS plugin

**Recommended Changes**:

```yaml
# Use containerd instead of docker
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nodeagent-file
spec:
  template:
    spec:
      nodeSelector:
        # Use EKS worker node labels
        karpenter.sh/provisioner-name: default
        node.kubernetes.io/instance-type: g4dn.12xlarge  # GPU nodes
      
      containers:
      - name: nodeagent
        image: inferx/inferx_na:${VERSION}
        securityContext:
          privileged: true
        volumeMounts:
        # Mount containerd socket instead
        - mountPath: /var/run/containerd/containerd.sock
          name: containerd-sock
        # Use EBS for snapshots (instead of hostPath)
        - mountPath: /opt/inferx/snapshot
          name: ebs-snapshot
        # Use EFS for shared data
        - mountPath: /opt/inferx/cache
          name: efs-cache
        # GPU access
        - mountPath: /dev/nvidia0
          name: nvidia-gpu-0
        - mountPath: /dev/nvidia-uvm
          name: nvidia-uvm
      
      volumes:
      - name: containerd-sock
        hostPath:
          path: /run/containerd/containerd.sock
      - name: ebs-snapshot
        awsElasticBlockStore:
          volumeID: vol-xxxxxxx  # Pre-create EBS volume
          fsType: ext4
      - name: efs-cache
        nfs:
          server: {EFS_SERVER}
          path: /cache
      - name: nvidia-gpu-0
        hostPath:
          path: /dev/nvidia0
      - name: nvidia-uvm
        hostPath:
          path: /dev/nvidia-uvm
```

### 8.3 Service Discovery

**Change from hardcoded DNS**:

Current:
```yaml
env:
- name: STATESVC_ADDR
  value: "http://statesvc:1237"
- name: ETCD_ADDRS
  value: "http://etcd:2379"
```

Better for EKS with DNS:
```yaml
env:
- name: STATESVC_ADDR
  value: "http://statesvc.inferx.svc.cluster.local:1237"
- name: ETCD_ADDRS
  value: "http://etcd.inferx.svc.cluster.local:2379"
```

Or use Kubernetes API:
```yaml
env:
- name: STATESVC_ADDR
  valueFrom:
    fieldRef:
      apiVersion: v1
      fieldPath: metadata.namespace
```

### 8.4 Storage Tier Configuration

**File: `nodeconfig/node.json` for EKS**

```json
{
  "snapshotDir": "/mnt/ebs/snapshot",      // EBS volume
  "enableBlobStore": true,
  "blobStoreType": "s3",                   // or "nfs"
  "blobStoreConfig": {
    "s3Bucket": "inferx-snapshots",
    "s3Region": "us-west-2",
    "s3Prefix": "snapshots/"
  }
}
```

### 8.5 etcd Persistence for EKS

```yaml
apiVersion: apps/v1
kind: StatefulSet  # Changed from Deployment
metadata:
  name: etcd
spec:
  serviceName: etcd
  replicas: 3  # HA cluster
  template:
    spec:
      containers:
      - image: quay.io/coreos/etcd:v3.5.13
        args:
        - "--name=$(HOSTNAME)"
        - "--initial-cluster=etcd-0=http://etcd-0.etcd:2380,etcd-1=http://etcd-1.etcd:2380,etcd-2=http://etcd-2.etcd:2380"
        volumeMounts:
        - name: etcd-storage
          mountPath: /var/lib/etcd
  volumeClaimTemplates:
  - metadata:
      name: etcd-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: gp3  # EBS gp3
      resources:
        requests:
          storage: 100Gi
```

---

## 9. Performance Characteristics

### Cold Start Latency Breakdown

**Without Snapshot** (Normal pod creation):
1. Pod creation (etcd) - 100ms
2. Docker image pull - 2-5 seconds (cached)
3. Container start - 500ms
4. Model loading (vLLM init) - 5-15 seconds
5. Health probe passes - 100ms
**Total: 8-20 seconds**

**With Snapshot** (restore from saved state):
1. Pod creation - 100ms
2. Snapshot restore (CPU + GPU state) - 200-800ms
3. Health probe passes - 100ms
**Total: 0.4-1.0 seconds**

### GPU Utilization

**Single-Pod Approach** (traditional):
- Pod A uses 100% of GPU 0
- Pod B must wait or use GPU 1
- Utilization: 10-20% (sporadic requests)

**InferX Approach** (high density + fractional allocation):
- Pod A uses 1/3 of GPU 0 (14GB VRAM reserved)
- Pod B uses 1/3 of GPU 0 (14GB VRAM reserved)
- Pod C uses 1/3 of GPU 0 (14GB VRAM reserved)
- All run simultaneously (different inference requests)
- Idle Pod D in GPU memory (snapshot preloaded)
- Idle Pod E on disk (snapshot pageable)
**Utilization: 80-90%** (dense scheduling + snapshot reuse)

---

## 10. Key Dependencies

**Rust Crates**:
- `tokio` - async runtime
- `tonic` - gRPC server/client
- `axum` - HTTP framework
- `etcd_client` - etcd integration
- `sqlx` - PostgreSQL async driver
- `serde_json` - JSON handling
- `opentelemetry` - distributed tracing

**External Services**:
- **etcd** - metadata store (3.5.13+)
- **PostgreSQL** - audit logging
- **Keycloak** - authentication (optional)
- **Node Agent** - per-node container management (separate Rust binary)
- **Docker/Containerd** - container runtime

**Deployment**:
- Kubernetes 1.24+
- NVIDIA GPU Plugin (for GPU device allocation)
- EBS/EFS (recommended for EKS)

---

## 11. Summary Table: Key Classes & Responsibilities

| Module | File | Lines | Responsibility |
|--------|------|-------|-----------------|
| **Scheduler** | scheduler_handler.rs | 2,976 | Pod allocation, resource tracking, GPU management |
| **Gateway** | http_gateway.rs | 1,686 | HTTP request routing, auth, response forwarding |
| **Function Agent Manager** | func_agent_mgr.rs | 893 | Per-function worker pool, scaling policy |
| **Function Worker** | func_worker.rs | 1,056 | HTTP connection pooling, request execution |
| **Gateway Repo** | gw_obj_repo.rs | 968 | Local cache of cluster objects |
| **etcd Store** | etcd_store.rs | 731 | Async etcd backend interface |
| **State Service** | state_svc.rs | 708 | Metadata management, object routing |
| **Node Config** | node_config.rs | 791 | Configuration loading, resource parsing |

---

## 12. What Needs EKS-Specific Adaptation

1. **Container Runtime**: DinD → containerd socket
2. **Volume Management**: hostPath → EBS/EFS
3. **GPU Assignment**: NVIDIA device plugin integration
4. **Snapshot Storage**: Local disk → S3/EBS
5. **Service Discovery**: Hardcoded DNS → Kubernetes DNS
6. **etcd Persistence**: Single-node → HA StatefulSet
7. **Logging**: Local files → CloudWatch/ELK
8. **Networking**: Host network → K8s networking + ingress
9. **Resource Quotas**: Per-node → Kubernetes ResourceQuota/LimitRange
10. **Monitoring**: Custom metrics → Prometheus via ServiceMonitor

