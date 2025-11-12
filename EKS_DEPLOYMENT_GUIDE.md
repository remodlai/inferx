# InferX EKS Deployment Implementation Guide

## Executive Summary

InferX is a GPU-accelerated serverless inference platform that achieves 2-second cold starts through container snapshots and 80%+ GPU utilization through intelligent multi-tenant scheduling. This guide covers adapting the current Kubernetes manifests (designed for on-premises) to AWS EKS with best practices for production deployment.

---

## 1. Critical Path Overview for EKS

### Request Flow (End-to-End)

```
User Request (HTTP/REST to ALB)
  ↓
API Gateway Pod (4000/tcp) - Route to inference function
  ├─ Authenticate (KeyCloak or API key)
  ├─ Look up function in cache (from State Service)
  ├─ Get scaling policy
  ├─ Call Scheduler gRPC to lease worker pod
  │
  └─ Scheduler Pod (1238/tcp) - GPU allocation orchestration
      ├─ Search for idle worker pod (same function, same GPU type)
      ├─ If found: transition pod state and return IP/port
      ├─ If not found: allocate node+GPU and create new pod
      │   ├─ Write pod spec to etcd
      │   └─ Node Agent watches and creates container (Docker)
      ├─ Wait for pod Ready state
      └─ Return pod IP/port/keepalive_flag
  
  Gateway creates HTTP connection to worker pod:80
    └─ POST /funccall with model inference payload
         ↓
    Worker Container (vLLM/TensorRT server) - Inference execution
      ├─ Load model on first request (if not in cache)
      ├─ Run inference
      ├─ Return result (JSON/streaming)
         ↓
    Gateway pools connection (if keepalive) or closes
      ├─ Return response to user
      └─ Call Scheduler.ReturnWorker() to mark pod Idle
```

### Architecture Diagram (EKS Specific)

```
┌─────────────────────────────────────────────────────────────┐
│ AWS EKS Cluster (inferx namespace)                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Control Plane (AWS Managed)                                │
│ - etcd (via AWS-managed control plane)                     │
│                                                             │
│ Data Plane:                                                │
│                                                             │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ Master Nodes (non-GPU, General Purpose)              │  │
│ │  - API Gateway (Deployment, replicas=2-3)           │  │
│ │  - Scheduler (Deployment, replicas=1)               │  │
│ │  - State Service (Deployment, replicas=1)           │  │
│ │  - etcd (StatefulSet, replicas=3, NVMe SSD)        │  │
│ │  - PostgreSQL Audit DB (StatefulSet, EBS)          │  │
│ │  - Redis Cache (optional)                           │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                             │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ GPU Worker Nodes (g4dn.12xlarge, g5.24xlarge)      │  │
│ │  - Node Agent DaemonSet (1 per node)                │  │
│ │  - Worker Pods (inference containers)               │  │
│ │    Created by Node Agent via containerd             │  │
│ │    Volume: EBS for snapshots                        │  │
│ │    GPU: NVIDIA Device Plugin                        │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                             │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ Storage Infrastructure                               │  │
│ │  - EBS (gp3/io1): Pod snapshots, etcd data          │  │
│ │  - EFS: Shared model cache (/cache/huggingface)    │  │
│ │  - S3: Archival snapshots, disaster recovery       │  │
│ │  - CloudWatch: Logs, metrics                        │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                             │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ Networking                                           │  │
│ │  - AWS Load Balancer Controller (ALB)               │  │
│ │  - Ingress: /funccall → API Gateway :4000           │  │
│ │  - Internal: gRPC between services                  │  │
│ │  - VPC CNI (AWS): Pod networking                    │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. GPU Allocation Strategy for EKS

### GPU Instance Types (Recommended)

| Instance | GPUs | VRAM | CPU | Memory | Best For |
|----------|------|------|-----|--------|----------|
| g4dn.12xlarge | 4×T4 | 4×16GB | 48 | 192GB | LLM 7B-13B |
| g5.24xlarge | 6×A10 | 6×24GB | 96 | 384GB | LLM 13B-70B |
| g4ad.16xlarge | 8×A100 (40GB) | 8×40GB | 64 | 256GB | LLM 70B+ |

### GPU Fractional Slicing Configuration

**Goal**: Run 3-4 models on single GPU simultaneously

**Example**: 1 x A10 (24GB) serving 3 models

```json
{
  "type": "function",
  "name": "qwen-7b-model-1",
  "resources": {
    "GPU": {
      "Count": 1,         // 1 GPU slot
      "vRam": 7500,       // Allocate 7.5GB VRAM (leave 1GB headroom)
      "Type": "A10"       // Request A10 specifically
    }
  }
}
```

**Scheduler Algorithm**:

```rust
fn AllocateGPU(node: &NodeStatus, required_vram: i64) -> Result<GPUSlot> {
    // 1. Find GPU with available VRAM
    for gpu in &node.gpus {
        if gpu.available_vram >= required_vram + CONTEXT_OVERHEAD {
            // 2. Allocate slice
            gpu.available_vram -= required_vram;
            return Ok(GPUSlot {
                index: gpu.index,
                allocated_vram: required_vram,
                CUDA_DEVICE: gpu.index,  // GPU 0, 1, 2, etc.
            });
        }
    }
    
    // 3. If no single GPU fits, search for multi-GPU allocation
    // (for large models needing tensor parallelism)
    Err(Error::InsufficientGPU)
}

// GPU Environment Variable Generation
fn GenerateGPUEnvVars(slot: GPUSlot) -> HashMap<String, String> {
    map! {
        "NVIDIA_VISIBLE_DEVICES" => slot.index.to_string(),
        "CUDA_VISIBLE_DEVICES" => slot.index.to_string(),
        "CUDA_DEVICE_ORDER" => "PCI_BUS_ID",
        "NVIDIA_MIG_CONFIG" => "",  // Multi-instance GPU not used
        "NVIDIA_MIG_MONITOR" => "0",
    }
}
```

### GPU Memory Accounting

```
Total GPU VRAM: 24 GB (A10)
├─ Model 1 (Qwen 7B): 7.5 GB allocated
├─ Model 2 (Mistral 7B): 7.5 GB allocated
├─ Model 3 (Llama 7B): 7.5 GB allocated
└─ Reserved (OS/frameworks): 2 GB

When Model 1 is idle:
├─ Snapshot preloaded to GPU memory: 7.5 GB
├─ Model 2 active: 7.5 GB
├─ Model 3 active: 7.5 GB
└─ Total utilization: 22.5 GB / 24 GB = 93.75% ✓
```

---

## 3. EKS Configuration Changes

### 3.1 Node Agent DaemonSet - containerd Implementation

**Current Code** (`k8s/nodeagent.yaml`):
```yaml
# Uses Docker-in-Docker via hostPath mount
volumeMounts:
  - mountPath: /var/lib/docker
    name: dind
```

**EKS-Optimized** (containerd):
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nodeagent
  namespace: inferx
spec:
  selector:
    matchLabels:
      app: nodeagent
  template:
    metadata:
      labels:
        app: nodeagent
    spec:
      # Use NVIDIA DPU nodes or GPU-enabled worker nodes
      nodeSelector:
        karpenter.sh/provisioner-name: gpu-nodes
        workload-type: gpu
      
      tolerations:
        - key: "workload-type"
          operator: "Equal"
          value: "gpu"
          effect: "NoSchedule"
      
      hostNetwork: false  # Use VPC CNI instead
      hostPID: true       # For container management
      hostIPC: false
      
      containers:
      - name: nodeagent
        image: inferx/inferx_na:${VERSION}
        imagePullPolicy: Always
        
        # Critical: Run as root to manage containers
        securityContext:
          privileged: true
          runAsUser: 0
          runAsGroup: 0
          capabilities:
            add:
              - SYS_ADMIN      # Container runtime control
              - SYS_PTRACE     # Process tracing for debugging
              - IPC_LOCK       # GPU memory pinning (hugepages)
              - SYS_RAWIO      # Direct hardware access
              - NET_ADMIN      # Network device management
              - SYS_RESOURCE   # Resource limit adjustment
        
        env:
        - name: RUN_SERVICE
          value: "NodeAgent"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: STATESVC_ADDR
          value: "http://statesvc.inferx.svc.cluster.local:1237"
        - name: CONTAINER_RUNTIME
          value: "containerd"  # NEW: Tell NodeAgent to use containerd
        - name: CONTAINERD_SOCKET
          value: "/run/containerd/containerd.sock"
        - name: ENABLE_GPU_SNAPSHOT
          value: "true"
        - name: GPU_SNAPSHOT_METHOD
          value: "cuda"  # or "dmem-cuda" for device memory
        - name: SNAPSHOT_DIR
          value: "/mnt/ebs/snapshots"
        - name: ALLOC_MEMORY  # From K8s resource limits
          valueFrom:
            resourceFieldRef:
              containerName: nodeagent
              resource: limits.memory
        - name: ALLOC_CPU
          valueFrom:
            resourceFieldRef:
              containerName: nodeagent
              resource: limits.cpu
        
        # Resource allocation for Node Agent itself
        resources:
          requests:
            cpu: "8"              # 8 full CPUs for container mgmt
            memory: "32Gi"        # 32GB for snapshots in RAM
            ephemeral-storage: "100Gi"  # For temporary files
          limits:
            cpu: "16"             # Up to 16 CPUs burst
            memory: "64Gi"
            ephemeral-storage: "100Gi"
        
        # Volume mounts for container management
        volumeMounts:
        # containerd socket (instead of Docker socket)
        - name: containerd-sock
          mountPath: /run/containerd/containerd.sock
          readOnly: false
        
        # Host container runtime data
        - name: containerd-data
          mountPath: /var/lib/containerd
          readOnly: false
        
        # EBS volume for snapshots (persistent, fast)
        - name: snapshots-ebs
          mountPath: /mnt/ebs/snapshots
        
        # Temp volume for snapshot working directory
        - name: snapshots-temp
          mountPath: /tmp/snapshots
        
        # Host device access for GPUs
        - name: nvidia-devices
          mountPath: /dev/nvidia0
          readOnly: false
        - name: nvidia-devices
          mountPath: /dev/nvidia1
          readOnly: false
        - name: nvidia-devices
          mountPath: /dev/nvidia2
          readOnly: false
        - name: nvidia-devices
          mountPath: /dev/nvidia3
          readOnly: false
        - name: nvidia-uvm
          mountPath: /dev/nvidia-uvm
          readOnly: false
        - name: nvidia-uvm-tools
          mountPath: /dev/nvidia-uvm-tools
          readOnly: false
        
        # System access
        - name: sys
          mountPath: /sys
          readOnly: false
        - name: proc
          mountPath: /proc
          readOnly: false
        - name: cgroup
          mountPath: /sys/fs/cgroup
          readOnly: false
        
        # Hugepages for GPU pinned memory
        - name: hugepages
          mountPath: /dev/hugepages
        
        # EFS for model cache (shared across nodes)
        - name: model-cache-efs
          mountPath: /cache/huggingface
        
        # Logging
        - name: logs
          mountPath: /opt/inferx/log
        
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - |
              curl -s http://localhost:8000/health || \
              nc -zv localhost 1233
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
        
        readinessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - |
              test -S /run/containerd/containerd.sock && \
              curl -s http://statesvc.inferx.svc.cluster.local:1237/health
          initialDelaySeconds: 10
          periodSeconds: 5
      
      # Volumes for Node Agent
      volumes:
      - name: containerd-sock
        hostPath:
          path: /run/containerd/containerd.sock
          type: Socket
      
      - name: containerd-data
        hostPath:
          path: /var/lib/containerd
          type: Directory
      
      # EBS volume (pre-provisioned)
      - name: snapshots-ebs
        awsElasticBlockStore:
          volumeID: ${SNAPSHOTS_EBS_ID}  # Set via helm values
          fsType: ext4
      
      # EmptyDir for temporary files
      - name: snapshots-temp
        emptyDir:
          medium: Memory
          sizeLimit: 50Gi
      
      # GPU devices
      - name: nvidia-devices
        hostPath:
          path: /dev/nvidia0
      
      - name: nvidia-uvm
        hostPath:
          path: /dev/nvidia-uvm
      
      - name: nvidia-uvm-tools
        hostPath:
          path: /dev/nvidia-uvm-tools
      
      # System access
      - name: sys
        hostPath:
          path: /sys
          type: Directory
      
      - name: proc
        hostPath:
          path: /proc
          type: Directory
      
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup
          type: Directory
      
      # Hugepages
      - name: hugepages
        hostPath:
          path: /dev/hugepages
          type: Directory
      
      # EFS (NFS backend)
      - name: model-cache-efs
        nfs:
          server: ${EFS_DNS}.efs.${AWS_REGION}.amazonaws.com
          path: /
      
      # Logs
      - name: logs
        emptyDir: {}
      
      restartPolicy: Always
      
      # Service account for AWS permissions (if using IRSA)
      serviceAccountName: nodeagent
      
      affinity:
        # Schedule on GPU nodes
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: karpenter.sh/provisioner-name
                operator: In
                values:
                - gpu-nodes
              - key: workload-type
                operator: In
                values:
                - gpu
        
        # Spread across different nodes
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - nodeagent
              topologyKey: kubernetes.io/hostname
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nodeagent
  namespace: inferx
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::${ACCOUNT_ID}:role/inferx-nodeagent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nodeagent
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["nodes"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nodeagent
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nodeagent
subjects:
- kind: ServiceAccount
  name: nodeagent
  namespace: inferx
```

### 3.2 Scheduler & Gateway Service Isolation

**Current** (single-node testing):
```yaml
env:
- name: ETCD_ADDRS
  value: "http://localhost:2379"  # assumes etcd on same pod!
```

**EKS-Recommended** (service discovery):
```yaml
env:
# Use K8s DNS (only works if services in same cluster)
- name: ETCD_ADDRS
  value: "http://etcd.inferx.svc.cluster.local:2379"

# Or use Kubernetes service endpoint
- name: ETCD_ADDRS
  valueFrom:
    fieldRef:
      fieldPath: status.namespace
# Then construct: http://etcd.${namespace}.svc.cluster.local:2379

# Better: External service with LoadBalancer
- name: ETCD_ADDRS
  value: "http://${ETCD_LB_DNS}:2379"
```

### 3.3 etcd HA Cluster for Production

**Current** (single-node):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: etcd
spec:
  replicas: 1
  template:
    spec:
      containers:
      - image: quay.io/coreos/etcd:v3.5.13
        args:
        - "--name=etcd-00"
        - "--data-dir=/opt/inferx/data/etcd"
```

**EKS-Recommended** (HA cluster):
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: etcd
  namespace: inferx
spec:
  serviceName: etcd  # Headless service for DNS
  replicas: 3        # HA quorum
  selector:
    matchLabels:
      app: etcd
  template:
    metadata:
      labels:
        app: etcd
    spec:
      nodeSelector:
        workload-type: control-plane  # Dedicated control nodes
      
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - etcd
            topologyKey: kubernetes.io/hostname
      
      containers:
      - name: etcd
        image: quay.io/coreos/etcd:v3.5.13
        
        # Use StatefulSet DNS names for cluster discovery
        args:
        - "--name=$(HOSTNAME)"
        - "--listen-client-urls=http://0.0.0.0:2379"
        - "--advertise-client-urls=http://$(HOSTNAME).etcd.inferx.svc.cluster.local:2379"
        - "--listen-peer-urls=http://0.0.0.0:2380"
        - "--advertise-peer-urls=http://$(HOSTNAME).etcd.inferx.svc.cluster.local:2380"
        - "--initial-cluster=etcd-0=http://etcd-0.etcd.inferx.svc.cluster.local:2380,etcd-1=http://etcd-1.etcd.inferx.svc.cluster.local:2380,etcd-2=http://etcd-2.etcd.inferx.svc.cluster.local:2380"
        - "--initial-cluster-state=new"
        - "--initial-advertise-peer-urls=http://$(HOSTNAME).etcd.inferx.svc.cluster.local:2380"
        - "--data-dir=/var/lib/etcd"
        - "--quota-backend-bytes=8589934592"  # 8GB limit
        - "--auto-compaction-retention=1h"    # Auto-compact hourly
        
        env:
        - name: HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        
        ports:
        - name: client
          containerPort: 2379
        - name: peer
          containerPort: 2380
        
        resources:
          requests:
            cpu: "2"
            memory: "4Gi"
          limits:
            cpu: "4"
            memory: "8Gi"
        
        volumeMounts:
        - name: etcd-data
          mountPath: /var/lib/etcd
        
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - ETCDCTL_API=3 etcdctl --endpoints=localhost:2379 member list
          initialDelaySeconds: 30
          periodSeconds: 10
      
      securityContext:
        runAsUser: 0
        runAsGroup: 0
        fsGroup: 0
  
  volumeClaimTemplates:
  - metadata:
      name: etcd-data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: etcd-io1  # High-performance EBS
      resources:
        requests:
          storage: 100Gi  # Size per replica (300GB total HA)

---
# Headless service for peer discovery
apiVersion: v1
kind: Service
metadata:
  name: etcd
  namespace: inferx
spec:
  clusterIP: None  # Headless
  selector:
    app: etcd
  ports:
  - name: client
    port: 2379
    targetPort: 2379
  - name: peer
    port: 2380
    targetPort: 2380

---
# Client service (for non-StatefulSet clients)
apiVersion: v1
kind: Service
metadata:
  name: etcd-client
  namespace: inferx
spec:
  type: LoadBalancer  # Or ClusterIP for internal use
  selector:
    app: etcd
  ports:
  - name: client
    port: 2379
    targetPort: 2379
```

---

## 4. Storage Tier Configuration for EKS

### 4.1 Snapshot Storage Strategy

**Hierarchical Storage**:
```
Level 1: GPU Memory (fastest)
  ├─ Preloaded snapshot: 0.5-2 GB
  ├─ Duration: While request processing
  └─ Access: Direct CUDA
     
Level 2: Node EBS gp3 (fast)
  ├─ Snapshot file: 10-40 GB per model
  ├─ Duration: 5-15 minutes (active pod)
  ├─ Purpose: Quick restore to GPU
  └─ EC2 Instance Store Option: NVMe SSD
     
Level 3: EFS (shared, slower)
  ├─ Model weights cache: 100-500 GB
  ├─ Duration: Persistent across pods
  ├─ Access: Shared by all pods
  └─ Examples: HuggingFace cache, GPTQ weights
     
Level 4: S3 (coldest)
  ├─ Archive/backup: Long-term storage
  ├─ Duration: Permanent
  ├─ Purpose: Disaster recovery, new deployment
  └─ Lifecycle: Auto-delete after 90 days
```

### 4.2 Configuration in node.json

```json
{
  "snapshotDir": "/mnt/ebs/snapshots",
  "enableBlobStore": true,
  "blobStoreConfig": {
    "type": "tiered",
    "tiers": [
      {
        "name": "ebs-gp3",
        "type": "awsEBS",
        "volumeId": "${SNAPSHOTS_VOL_ID}",
        "fsType": "ext4",
        "mountPath": "/mnt/ebs/snapshots",
        "priority": 10,
        "maxSize": "500Gi",
        "accessLatency": "50ms"
      },
      {
        "name": "efs-cache",
        "type": "awsEFS",
        "fileSystemId": "${EFS_ID}",
        "mountPath": "/mnt/efs/cache",
        "priority": 5,
        "maxSize": "1Ti",
        "accessLatency": "300ms",
        "accessPoints": {
          "huggingface": "/huggingface",
          "model-weights": "/weights"
        }
      },
      {
        "name": "s3-archive",
        "type": "awsS3",
        "bucket": "inferx-snapshots",
        "region": "us-west-2",
        "priority": 1,
        "accessLatency": "2000ms",
        "lifecycle": {
          "expiration": 90,
          "transitionToGlacier": 30
        }
      }
    ]
  },
  "snapshotConfig": {
    "compressionFormat": "zstd",
    "compressionLevel": 3,
    "includeGPUMemory": true,
    "includeCPUMemory": false,
    "maxSnapshotSize": "50Gi",
    "retentionPolicy": {
      "maxSnapshots": 10,
      "minAge": "1h",
      "maxAge": "7d"
    }
  }
}
```

---

## 5. Pod Allocation Logic for EKS

### 5.1 Node Selection Algorithm

```rust
fn SelectNodeForPod(
    available_nodes: &[EKSNode],
    pod_requirements: &PodResourceRequest,
    placement_hints: &PlacementHints,
) -> Result<EKSNode> {
    
    // Filter 1: Node readiness
    let ready_nodes: Vec<_> = available_nodes.iter()
        .filter(|n| n.kubernetes_state == NodeReady 
                && n.agent_ready)
        .collect();
    
    // Filter 2: Resource sufficiency
    let feasible_nodes: Vec<_> = ready_nodes.iter()
        .filter(|n| {
            n.available_cpu >= pod_requirements.cpu &&
            n.available_memory >= pod_requirements.memory &&
            n.available_gpus.iter()
                .any(|gpu| gpu.available_vram >= pod_requirements.gpu_vram)
        })
        .collect();
    
    // Filter 3: Placement constraints
    let valid_nodes: Vec<_> = feasible_nodes.iter()
        .filter(|n| {
            // GPU type matching
            if let Some(required_type) = &placement_hints.gpu_type {
                n.available_gpus.iter()
                    .any(|gpu| gpu.model == *required_type)
            } else {
                true  // Any GPU type acceptable
            }
        })
        .filter(|n| {
            // Availability Zone preference (for multi-AZ)
            if let Some(preferred_az) = &placement_hints.preferred_az {
                n.availability_zone == *preferred_az
            } else {
                true
            }
        })
        .collect();
    
    if valid_nodes.is_empty() {
        return Err(Error::NoSuitableNode);
    }
    
    // Scoring strategy: Bin-packing for density
    let best_node = valid_nodes.iter()
        .min_by_key(|n| {
            // Score: (lower = better)
            // 1. Prioritize nodes with fewer pods (spread load)
            // 2. Within same pod count, prefer nodes with less available capacity
            //    (packs pods densely)
            (
                n.pod_count,                    // Primary: Pod count
                -(n.available_memory as i64),   // Secondary: Less available mem
                -(n.available_cpus as i64),     // Tertiary: Less available CPU
            )
        })?;
    
    return Ok(best_node.clone());
}
```

### 5.2 Multi-AZ & Regional Distribution

```yaml
# Scheduler config for multi-region
spec:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: app
              operator: In
              values:
              - scheduler
          topologyKey: topology.kubernetes.io/zone
```

---

## 6. Monitoring & Observability

### 6.1 CloudWatch Integration

```yaml
# InferX Services with CloudWatch agent sidecar
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gateway
spec:
  template:
    spec:
      containers:
      - name: gateway
        image: inferx/inferx_platform:${VERSION}
        env:
        - name: ENABLE_CLOUDWATCH
          value: "true"
        - name: CLOUDWATCH_REGION
          value: ${AWS_REGION}
        - name: CLOUDWATCH_LOG_GROUP
          value: /inferx/gateway
      
      - name: cloudwatch-agent
        image: amazon/cloudwatch-agent:latest
        volumeMounts:
        - name: cloudwatch-config
          mountPath: /etc/amazon/amazon-cloudwatch-agent.json
          subPath: cloudwatch-config.json
      
      volumes:
      - name: cloudwatch-config
        configMap:
          name: cloudwatch-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloudwatch-config
  namespace: inferx
data:
  cloudwatch-config.json: |
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/opt/inferx/log/gateway.log",
                "log_group_name": "/inferx/gateway",
                "log_stream_name": "{instance_id}",
                "timezone": "UTC"
              },
              {
                "file_path": "/opt/inferx/log/scheduler.log",
                "log_group_name": "/inferx/scheduler",
                "log_stream_name": "{instance_id}"
              }
            ]
          }
        }
      },
      "metrics": {
        "namespace": "InferX",
        "metrics_collected": {
          "prometheus": {
            "metrics_path": "/metrics",
            "ecs_service_discovery": false
          }
        }
      }
    }
```

### 6.2 Prometheus Metrics

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: inferx
  namespace: inferx
spec:
  selector:
    matchLabels:
      monitoring: "true"
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

---

## 7. Cost Optimization for EKS

### 7.1 Spot Instance Integration (via Karpenter)

```yaml
apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: gpu-spot
spec:
  requirements:
  - key: karpenter.sh/capacity-type
    operator: In
    values: ["spot", "on-demand"]
  - key: node.kubernetes.io/instance-type
    operator: In
    values: ["g4dn.12xlarge", "g4dn.24xlarge"]
  - key: kubernetes.io/arch
    operator: In
    values: ["amd64"]
  
  limits:
    resources:
      cpu: 1000
      memory: 1000Gi
  
  ttlSecondsAfterEmpty: 30
  ttlSecondsUntilExpired: 2592000
```

### 7.2 Resource Requests (Prevent Over-Provisioning)

```yaml
# Scheduler deployment
resources:
  requests:
    cpu: "2"        # Actual usage ~1 CPU
    memory: "2Gi"   # Actual usage ~1 GB
  limits:
    cpu: "4"
    memory: "4Gi"
```

---

## 8. Security Best Practices

### 8.1 IRSA (IAM Roles for Service Accounts)

```bash
# Allow Node Agent to access EBS and S3
eksctl create iamserviceaccount \
  --cluster=inferx \
  --namespace=inferx \
  --name=nodeagent \
  --attach-policy-arn=arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
  --approve
```

### 8.2 Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inferx-network-policy
  namespace: inferx
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: inferx
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: inferx
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53  # DNS
```

---

## 9. Deployment Checklist

- [ ] EKS cluster created with GPU worker node groups
- [ ] NVIDIA device plugin installed
- [ ] EBS volumes provisioned for snapshots
- [ ] EFS provisioned for model cache
- [ ] etcd HA cluster deployed (StatefulSet)
- [ ] PostgreSQL audit database deployed
- [ ] Node Agent DaemonSet configured for containerd
- [ ] Scheduler service exposed
- [ ] Gateway service exposed via ALB
- [ ] State Service deployed
- [ ] CloudWatch logging configured
- [ ] Prometheus/Grafana for metrics (optional)
- [ ] Karpenter autoscaling configured
- [ ] IAM roles configured (IRSA)
- [ ] Network policies configured
- [ ] Secrets management configured (AWS Secrets Manager)

---

## 10. Deployment Command Reference

```bash
# Set up namespace
kubectl create namespace inferx

# Deploy etcd HA cluster
kubectl apply -f k8s/etcd-ha.yaml

# Deploy State Service
kubectl apply -f k8s/statesvc.yaml

# Deploy Scheduler
kubectl apply -f k8s/scheduler.yaml

# Deploy Gateway
kubectl apply -f k8s/gateway.yaml

# Deploy Node Agent DaemonSet
kubectl apply -f k8s/nodeagent-eks.yaml

# Verify deployments
kubectl get all -n inferx

# Check logs
kubectl logs -n inferx deployment/gateway -f
kubectl logs -n inferx daemonset/nodeagent -f
```

---

## References

- InferX GitHub: https://github.com/inferx-net/inferx
- EKS Best Practices: https://aws.github.io/aws-eks-best-practices/
- Karpenter: https://karpenter.sh/
- etcd Operator: https://github.com/etcd-io/etcd-operator
