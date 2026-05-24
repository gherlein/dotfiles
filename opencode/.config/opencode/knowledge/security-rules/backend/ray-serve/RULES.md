# Ray Serve Security Rules

Security rules for Ray Serve distributed model serving in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Deployment Security

### Rule: Secure Deployment Configuration

**Level**: `strict`

**When**: Deploying Ray Serve applications.

**Do**:
```python
from ray import serve
from ray.serve import Application
from ray.serve.config import HTTPOptions
import os

# Safe: Secure deployment with resource limits
@serve.deployment(
    name="secure_model",
    num_replicas=2,
    max_concurrent_queries=100,
    # Resource limits per replica
    ray_actor_options={
        "num_cpus": 1,
        "num_gpus": 0.5,
        "memory": 2 * 1024 * 1024 * 1024,  # 2GB
    },
    # Health check configuration
    health_check_period_s=10,
    health_check_timeout_s=30,
)
class SecureModelDeployment:
    def __init__(self):
        # Load model securely
        import torch
        model_path = os.environ.get("MODEL_PATH")
        if not model_path:
            raise ValueError("MODEL_PATH not set")

        # Use TorchScript (safe) instead of pickle
        self.model = torch.jit.load(model_path)
        self.model.eval()

        # Set limits
        self.max_input_size = 10_000_000  # 10MB
        self.max_batch_size = 32

    async def __call__(self, request):
        # Validate request
        data = await request.body()

        if len(data) > self.max_input_size:
            return {"error": "Input too large"}, 400

        # Process safely
        result = self._predict(data)
        return {"result": result}

    def _predict(self, data: bytes):
        import torch
        import numpy as np

        # Safe deserialization
        arr = np.frombuffer(data, dtype=np.float32)
        tensor = torch.from_numpy(arr)

        with torch.no_grad():
            output = self.model(tensor)

        return output.numpy().tolist()

# Safe: Secure serve configuration
serve_config = {
    "http_options": HTTPOptions(
        host="127.0.0.1",  # Localhost only
        port=8000,
        # Request limits
        request_timeout_s=30,
    ),
    "logging_config": {
        "encoding": "JSON",
        "enable_access_log": True,
    }
}

# Safe: Deploy with authentication proxy
app = SecureModelDeployment.bind()
serve.run(app, **serve_config)
```

**Don't**:
```python
# VULNERABLE: No resource limits
@serve.deployment
class UnlimitedDeployment:
    pass  # Can consume all resources

# VULNERABLE: Public binding
serve_config = {
    "http_options": HTTPOptions(
        host="0.0.0.0",  # Exposed to all
        port=8000
    )
}

# VULNERABLE: Pickle-based model loading
@serve.deployment
class UnsafeModel:
    def __init__(self):
        import pickle
        self.model = pickle.load(open("model.pkl", "rb"))  # RCE

# VULNERABLE: No request validation
@serve.deployment
class NoValidation:
    async def __call__(self, request):
        data = await request.json()
        return self.model(data)  # Could be huge
```

**Why**: Unrestricted deployments enable resource exhaustion, denial of service, or code execution through unsafe deserialization.

**Refs**: CWE-400, CWE-502, OWASP LLM04

---

## Autoscaling Security

### Rule: Implement Secure Autoscaling Policies

**Level**: `strict`

**When**: Configuring autoscaling for Ray Serve deployments.

**Do**:
```python
from ray import serve
from ray.serve.config import AutoscalingConfig

# Safe: Bounded autoscaling
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        min_replicas=1,
        max_replicas=10,  # Hard limit
        target_num_ongoing_requests_per_replica=10,
        # Gradual scaling
        upscale_delay_s=30,
        downscale_delay_s=60,
        # Metrics window
        metrics_interval_s=10,
        look_back_period_s=30,
    ),
    # Per-replica limits
    ray_actor_options={
        "num_cpus": 1,
        "memory": 2 * 1024 * 1024 * 1024,
    },
    max_concurrent_queries=50,
)
class SecureAutoscaledModel:
    def __init__(self):
        self.model = self._load_model()

    async def __call__(self, request):
        # Implementation with validation
        pass

# Safe: Resource-aware autoscaling
def get_cluster_resources():
    import ray
    resources = ray.cluster_resources()
    return {
        "cpu": resources.get("CPU", 0),
        "memory": resources.get("memory", 0),
        "gpu": resources.get("GPU", 0)
    }

def calculate_safe_max_replicas(
    cpu_per_replica: float,
    memory_per_replica: float,
    safety_margin: float = 0.8
) -> int:
    resources = get_cluster_resources()

    max_by_cpu = int(
        (resources["cpu"] * safety_margin) / cpu_per_replica
    )
    max_by_memory = int(
        (resources["memory"] * safety_margin) / memory_per_replica
    )

    return min(max_by_cpu, max_by_memory, 100)  # Hard cap at 100

# Safe: Deployment with calculated limits
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        min_replicas=1,
        max_replicas=calculate_safe_max_replicas(1, 2 * 1024**3),
    )
)
class ResourceAwareModel:
    pass
```

**Don't**:
```python
# VULNERABLE: Unbounded autoscaling
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        min_replicas=1,
        max_replicas=1000,  # Can exhaust cluster
    )
)
class UnboundedModel:
    pass

# VULNERABLE: No per-replica limits
@serve.deployment(
    autoscaling_config=AutoscalingConfig(max_replicas=100)
    # No ray_actor_options - unlimited resources per replica
)
class UnlimitedReplicas:
    pass

# VULNERABLE: Aggressive scaling
@serve.deployment(
    autoscaling_config=AutoscalingConfig(
        upscale_delay_s=1,  # Too fast
        downscale_delay_s=1,
        max_replicas=100
    )
)
class AggressiveScaling:
    pass
```

**Why**: Unbounded autoscaling can exhaust cluster resources, causing cascading failures and enabling resource-based DoS attacks.

**Refs**: CWE-400, CWE-770

---

## Serialization Security

### Rule: Use Safe Serialization for Ray Objects

**Level**: `strict`

**When**: Passing objects between Ray actors and deployments.

**Do**:
```python
from ray import serve
import ray
import numpy as np

# Safe: Use supported serialization types
@serve.deployment
class SafeSerializer:
    async def __call__(self, request):
        data = await request.json()

        # Safe types for Ray serialization
        # numpy arrays, torch tensors, basic Python types
        arr = np.array(data["input"], dtype=np.float32)

        # Process in actor
        result = await self._process_remote(arr)
        return {"result": result.tolist()}

    async def _process_remote(self, arr: np.ndarray):
        # Ray handles numpy serialization safely
        return self.model.predict(arr)

# Safe: Custom serialization with validation
import msgpack

@serve.deployment
class SecureCustomSerializer:
    def __init__(self):
        self.allowed_types = {np.ndarray, list, dict, str, int, float}

    async def __call__(self, request):
        data = await request.body()

        # Use msgpack instead of pickle
        try:
            unpacked = msgpack.unpackb(data, raw=False)
        except Exception:
            return {"error": "Invalid serialization"}, 400

        # Validate types
        if not self._validate_types(unpacked):
            return {"error": "Invalid data types"}, 400

        return {"result": self._process(unpacked)}

    def _validate_types(self, obj, depth=0):
        if depth > 10:  # Prevent deep nesting attacks
            return False

        if isinstance(obj, dict):
            return all(
                self._validate_types(v, depth + 1)
                for v in obj.values()
            )
        elif isinstance(obj, list):
            return all(
                self._validate_types(v, depth + 1)
                for v in obj
            )
        else:
            return type(obj) in {str, int, float, bool, type(None)}

# Safe: TorchScript for model serialization
import torch

@serve.deployment
class SafeModelSerializer:
    def __init__(self, model_path: str):
        # TorchScript is safe (no arbitrary code execution)
        self.model = torch.jit.load(model_path)

    async def __call__(self, request):
        data = await request.json()
        tensor = torch.tensor(data["input"])

        with torch.no_grad():
            output = self.model(tensor)

        return {"output": output.tolist()}
```

**Don't**:
```python
# VULNERABLE: Pickle serialization
import pickle

@serve.deployment
class PickleDeployment:
    async def __call__(self, request):
        data = await request.body()
        obj = pickle.loads(data)  # Arbitrary code execution
        return self.model(obj)

# VULNERABLE: Eval for deserialization
@serve.deployment
class EvalDeployment:
    async def __call__(self, request):
        data = await request.json()
        obj = eval(data["code"])  # Code injection
        return obj

# VULNERABLE: No type validation
@serve.deployment
class NoValidation:
    async def __call__(self, request):
        data = await request.json()
        return self.model(data)  # Any structure accepted
```

**Why**: Unsafe serialization like pickle allows arbitrary code execution when deserializing malicious payloads.

**Refs**: CWE-502, CWE-94, OWASP LLM05

---

## Multi-Application Security

### Rule: Isolate Ray Serve Applications

**Level**: `strict`

**When**: Running multiple applications on same Ray cluster.

**Do**:
```python
from ray import serve
from ray.serve.config import HTTPOptions
import os

# Safe: Namespace isolation
serve.start(
    detached=True,
    http_options=HTTPOptions(
        host="127.0.0.1",
        port=8000
    ),
    # Use namespaces for isolation
    namespace="production"
)

# Safe: Application-level resource quotas
@serve.deployment(
    name="app_a_model",
    ray_actor_options={
        "num_cpus": 2,
        "memory": 4 * 1024**3,
        # Namespace for resource tracking
        "namespace": "app_a"
    }
)
class AppAModel:
    pass

@serve.deployment(
    name="app_b_model",
    ray_actor_options={
        "num_cpus": 2,
        "memory": 4 * 1024**3,
        "namespace": "app_b"
    }
)
class AppBModel:
    pass

# Safe: Route isolation with authentication
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import APIKeyHeader

app = FastAPI()
api_key_header = APIKeyHeader(name="X-API-Key")

# Different keys for different apps
APP_KEYS = {
    "app_a": os.environ.get("APP_A_KEY"),
    "app_b": os.environ.get("APP_B_KEY"),
}

async def verify_app_key(
    app_name: str,
    api_key: str = Depends(api_key_header)
):
    if APP_KEYS.get(app_name) != api_key:
        raise HTTPException(status_code=401)
    return api_key

@serve.deployment
@serve.ingress(app)
class Router:
    def __init__(self, app_a_handle, app_b_handle):
        self.handles = {
            "app_a": app_a_handle,
            "app_b": app_b_handle
        }

    @app.post("/{app_name}/predict")
    async def predict(
        self,
        app_name: str,
        data: dict,
        _: str = Depends(lambda: verify_app_key(app_name))
    ):
        if app_name not in self.handles:
            raise HTTPException(404)

        return await self.handles[app_name].remote(data)
```

**Don't**:
```python
# VULNERABLE: Shared namespace
serve.start(detached=True)  # Default namespace

@serve.deployment(name="model_a")
class ModelA:
    pass

@serve.deployment(name="model_b")
class ModelB:
    pass
# Both in same namespace - can interfere

# VULNERABLE: No resource isolation
@serve.deployment
class SharedResources:
    # No ray_actor_options - competes for all resources
    pass

# VULNERABLE: No authentication per app
@serve.deployment
class OpenRouter:
    async def __call__(self, request):
        app = request.path.split("/")[1]
        # Anyone can access any app
        return await self.handles[app].remote(request)
```

**Why**: Without isolation, applications can interfere with each other, access unauthorized data, or exhaust shared resources.

**Refs**: CWE-269, CWE-200

---

## Composition Security

### Rule: Secure Model Composition Pipelines

**Level**: `strict`

**When**: Building pipelines with multiple deployments.

**Do**:
```python
from ray import serve

# Safe: Validated pipeline with type checking
@serve.deployment
class Preprocessor:
    async def __call__(self, data: dict) -> dict:
        # Validate input
        if "image" not in data:
            raise ValueError("Missing image field")

        if len(data["image"]) > 10_000_000:
            raise ValueError("Image too large")

        # Process and return validated output
        processed = self._preprocess(data["image"])
        return {"processed": processed, "metadata": data.get("metadata", {})}

@serve.deployment
class Classifier:
    async def __call__(self, data: dict) -> dict:
        # Validate preprocessor output
        if "processed" not in data:
            raise ValueError("Invalid preprocessor output")

        result = self._classify(data["processed"])
        return {"class": result, "metadata": data.get("metadata", {})}

@serve.deployment
class Pipeline:
    def __init__(self, preprocessor, classifier):
        self.preprocessor = preprocessor
        self.classifier = classifier

    async def __call__(self, request):
        data = await request.json()

        # Validate initial input
        if not isinstance(data, dict):
            return {"error": "Invalid input format"}, 400

        try:
            # Pipeline with error handling
            prep_result = await self.preprocessor.remote(data)
            class_result = await self.classifier.remote(prep_result)

            return class_result

        except ValueError as e:
            return {"error": str(e)}, 400
        except Exception as e:
            # Log but don't expose internal errors
            import logging
            logging.error(f"Pipeline error: {e}")
            return {"error": "Internal error"}, 500

# Safe: Build pipeline with dependency injection
preprocessor = Preprocessor.bind()
classifier = Classifier.bind()
pipeline = Pipeline.bind(preprocessor, classifier)

serve.run(pipeline)
```

**Don't**:
```python
# VULNERABLE: No validation between stages
@serve.deployment
class UnsafePipeline:
    async def __call__(self, request):
        data = await request.json()
        # No validation - any data flows through
        result1 = await self.step1.remote(data)
        result2 = await self.step2.remote(result1)
        return result2

# VULNERABLE: Error information leakage
@serve.deployment
class LeakyPipeline:
    async def __call__(self, request):
        try:
            return await self.process(request)
        except Exception as e:
            return {"error": str(e), "trace": traceback.format_exc()}
            # Exposes internal details

# VULNERABLE: Circular dependencies
step_a = StepA.bind(step_b)
step_b = StepB.bind(step_a)  # Circular
```

**Why**: Unvalidated data flow between pipeline stages can propagate malicious inputs or enable information leakage through error messages.

**Refs**: CWE-20, CWE-209, OWASP LLM04

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure deployment configuration | strict | CWE-400, CWE-502 |
| Implement secure autoscaling policies | strict | CWE-400, CWE-770 |
| Use safe serialization for Ray objects | strict | CWE-502, CWE-94 |
| Isolate Ray Serve applications | strict | CWE-269, CWE-200 |
| Secure model composition pipelines | strict | CWE-20, CWE-209 |

---

## Version History

- **v1.0.0** - Initial Ray Serve security rules
