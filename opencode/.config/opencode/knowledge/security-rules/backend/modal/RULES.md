# Modal Security Rules

Security rules for Modal serverless AI deployment in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Function Security

### Rule: Secure Modal Function Configuration

**Level**: `strict`

**When**: Defining Modal functions and classes.

**Do**:
```python
import modal
from modal import Image, Secret, Stub

# Safe: Define stub with explicit configuration
stub = modal.Stub(
    name="secure-inference",
    # Use specific secrets, not all
    secrets=[modal.Secret.from_name("model-api-key")]
)

# Safe: Secure image with pinned dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "torch==2.0.1",
        "transformers==4.30.0",
        "numpy==1.24.0"
    )
    # Don't run as root
    .run_commands("useradd -m appuser")
)

# Safe: Function with resource limits and validation
@stub.function(
    image=image,
    gpu="T4",  # Specific GPU type
    memory=8192,  # Memory limit
    timeout=300,  # 5 minute timeout
    retries=2,
    # Concurrency limits
    concurrency_limit=10,
    allow_concurrent_inputs=5
)
def secure_inference(input_data: dict) -> dict:
    # Validate input
    if not isinstance(input_data, dict):
        raise ValueError("Invalid input type")

    if "prompt" not in input_data:
        raise ValueError("Missing prompt")

    prompt = input_data["prompt"]
    if len(prompt) > 10000:
        raise ValueError("Prompt too long")

    # Load model safely
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model = AutoModelForCausalLM.from_pretrained(
        "model-name",
        trust_remote_code=False  # CRITICAL
    )
    tokenizer = AutoTokenizer.from_pretrained(
        "model-name",
        trust_remote_code=False
    )

    # Generate with limits
    inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
    outputs = model.generate(**inputs, max_new_tokens=256)
    result = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return {"result": result}

# Safe: Class with lifecycle management
@stub.cls(
    image=image,
    gpu="T4",
    memory=8192,
    timeout=300,
    container_idle_timeout=60  # Clean up idle containers
)
class SecureModel:
    def __enter__(self):
        # Initialize model once per container
        from transformers import pipeline
        self.pipe = pipeline(
            "text-generation",
            model="gpt2",
            trust_remote_code=False
        )
        self.max_input_length = 1000

    @modal.method()
    def generate(self, prompt: str, max_tokens: int = 100) -> str:
        # Validate inputs
        if len(prompt) > self.max_input_length:
            raise ValueError("Prompt too long")

        if max_tokens > 500:
            max_tokens = 500  # Cap max tokens

        result = self.pipe(prompt, max_new_tokens=max_tokens)
        return result[0]["generated_text"]
```

**Don't**:
```python
# VULNERABLE: No resource limits
@stub.function()
def unlimited_function(data):
    return process(data)  # Can run forever

# VULNERABLE: Trust remote code
@stub.function(image=image)
def unsafe_model(prompt: str):
    model = AutoModel.from_pretrained(
        user_model_name,
        trust_remote_code=True  # RCE risk
    )

# VULNERABLE: No input validation
@stub.function()
def no_validation(data):
    return model(data)  # Any size/type

# VULNERABLE: Unpinned dependencies
image = modal.Image.debian_slim().pip_install(
    "torch",  # Gets latest - could break or have vulns
    "transformers"
)
```

**Why**: Unrestricted functions enable resource exhaustion, code execution through unsafe models, and denial of service.

**Refs**: CWE-400, CWE-502, OWASP LLM04

---

## Secrets Management

### Rule: Secure Modal Secrets Handling

**Level**: `strict`

**When**: Managing secrets and environment variables.

**Do**:
```python
import modal
import os

# Safe: Use Modal secrets with minimal scope
stub = modal.Stub("secure-app")

# Safe: Reference specific secrets
@stub.function(
    secrets=[
        modal.Secret.from_name("openai-key"),  # Named secret
    ]
)
def call_api():
    # Access secret from environment
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("API key not configured")

    # Use the secret
    return make_api_call(api_key)

# Safe: Create secrets from dict (for deployment)
"""
# CLI command to create secret
modal secret create model-config \
    MODEL_NAME=gpt-4 \
    MAX_TOKENS=1000
# Never include actual keys in commands - use interactive mode
"""

# Safe: Environment-specific secrets
@stub.function(
    secrets=[
        modal.Secret.from_name(
            "prod-api-key" if os.environ.get("ENV") == "prod"
            else "dev-api-key"
        )
    ]
)
def environment_aware():
    pass

# Safe: Multiple secrets with isolation
@stub.function(
    secrets=[
        modal.Secret.from_name("db-credentials"),
        modal.Secret.from_name("api-key"),
    ]
)
def multi_secret_function():
    db_pass = os.environ["DB_PASSWORD"]  # From db-credentials
    api_key = os.environ["API_KEY"]  # From api-key
    # Each secret has only necessary values

# Safe: Don't log secrets
@stub.function(secrets=[modal.Secret.from_name("api-key")])
def safe_logging():
    api_key = os.environ["API_KEY"]

    # Log operation, not secret
    print(f"Making API call with key length: {len(api_key)}")

    # Never log the actual key
    result = call_api(api_key)
    return result
```

**Don't**:
```python
# VULNERABLE: Hardcoded secrets
@stub.function()
def hardcoded_secret():
    api_key = "sk-1234567890abcdef"  # Exposed in code
    return call_api(api_key)

# VULNERABLE: Secret in image build
image = modal.Image.debian_slim().run_commands(
    "echo 'API_KEY=secret' >> /etc/environment"  # In image layer
)

# VULNERABLE: All secrets attached
stub = modal.Stub(
    secrets=[modal.Secret.from_name("all-secrets")]  # Overly broad
)

# VULNERABLE: Logging secrets
@stub.function(secrets=[modal.Secret.from_name("api-key")])
def log_secret():
    api_key = os.environ["API_KEY"]
    print(f"Using key: {api_key}")  # Exposed in logs

# VULNERABLE: Return secrets
@stub.function(secrets=[modal.Secret.from_name("api-key")])
def return_secret():
    return {"key": os.environ["API_KEY"]}  # Sent to caller
```

**Why**: Exposed secrets enable unauthorized API access, data theft, and financial abuse of cloud resources.

**Refs**: CWE-798, CWE-532, OWASP A07:2025

---

## Container Security

### Rule: Harden Modal Container Images

**Level**: `strict`

**When**: Building custom Modal images.

**Do**:
```python
import modal

# Safe: Minimal base image with security hardening
image = (
    modal.Image.debian_slim(python_version="3.11")
    # Install only needed packages
    .apt_install("libgomp1")  # For numpy
    # Pin all dependencies
    .pip_install(
        "torch==2.0.1",
        "numpy==1.24.0",
        # No dev dependencies
    )
    # Create non-root user
    .run_commands(
        "useradd -m -u 1000 appuser",
        "mkdir -p /app && chown appuser:appuser /app"
    )
    # Set working directory
    .workdir("/app")
    # Copy only needed files
    .copy_local_file("model.py", "/app/model.py")
)

# Safe: Use micromamba for faster, smaller images
image = (
    modal.Image.micromamba(python_version="3.11")
    .micromamba_install(
        "pytorch",
        "numpy",
        channels=["pytorch", "conda-forge"]
    )
    .pip_install("transformers==4.30.0")
)

# Safe: Multi-stage build pattern
base_image = modal.Image.debian_slim().pip_install("torch==2.0.1")

# Build model artifacts in separate step
@stub.function(image=base_image)
def build_model():
    # Download and process model
    pass

# Use lightweight inference image
inference_image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch==2.0.1", "transformers==4.30.0")
)

@stub.function(image=inference_image)
def inference():
    pass

# Safe: Scan image for vulnerabilities
"""
# Use trivy or similar scanner
trivy image modal-image:latest
"""
```

**Don't**:
```python
# VULNERABLE: Full base image
image = modal.Image.from_registry("python:3.11")  # Large attack surface

# VULNERABLE: Run as root
image = modal.Image.debian_slim()
# Default runs as root

# VULNERABLE: Install unnecessary tools
image = (
    modal.Image.debian_slim()
    .apt_install(
        "curl", "wget", "git", "ssh",  # Attack tools
        "build-essential"
    )
)

# VULNERABLE: Copy all files
image = modal.Image.debian_slim().copy_local_dir(".", "/app")
# Includes .env, .git, secrets

# VULNERABLE: Unpinned dependencies from registry
image = modal.Image.from_registry("pytorch/pytorch")  # Unknown version
```

**Why**: Bloated images with root access and unnecessary tools increase attack surface and enable privilege escalation.

**Refs**: CWE-250, CWE-269, OWASP A05:2025

---

## Web Endpoint Security

### Rule: Secure Modal Web Endpoints

**Level**: `strict`

**When**: Exposing Modal functions as web endpoints.

**Do**:
```python
import modal
from modal import web_endpoint, asgi_app
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field
import os

stub = modal.Stub("secure-api")

# Safe: Input validation with Pydantic
class PredictionRequest(BaseModel):
    prompt: str = Field(..., max_length=10000)
    max_tokens: int = Field(default=100, le=1000, ge=1)
    temperature: float = Field(default=0.7, ge=0, le=2)

class PredictionResponse(BaseModel):
    result: str
    tokens_used: int

# Safe: Web endpoint with validation and auth
@stub.function(secrets=[modal.Secret.from_name("api-keys")])
@web_endpoint(method="POST")
def secure_predict(
    request: PredictionRequest,
    authorization: str = Header(...)
) -> PredictionResponse:
    # Validate API key
    valid_keys = os.environ.get("API_KEYS", "").split(",")
    token = authorization.replace("Bearer ", "")

    if token not in valid_keys:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Process request
    result = generate(request.prompt, request.max_tokens)

    return PredictionResponse(
        result=result,
        tokens_used=len(result.split())
    )

# Safe: Full FastAPI app with security
app = FastAPI()

# Rate limiting state
from collections import defaultdict
from time import time
request_counts = defaultdict(list)

@app.middleware("http")
async def rate_limit(request, call_next):
    client = request.client.host
    now = time()

    # Clean old requests
    request_counts[client] = [
        t for t in request_counts[client] if now - t < 60
    ]

    if len(request_counts[client]) >= 60:
        raise HTTPException(429, "Rate limit exceeded")

    request_counts[client].append(now)
    return await call_next(request)

@app.post("/predict", response_model=PredictionResponse)
async def predict(
    request: PredictionRequest,
    authorization: str = Header(...)
):
    # Auth check
    if not verify_token(authorization):
        raise HTTPException(401, "Unauthorized")

    # Process
    return await process_prediction(request)

@stub.function(secrets=[modal.Secret.from_name("api-keys")])
@asgi_app()
def fastapi_app():
    return app
```

**Don't**:
```python
# VULNERABLE: No authentication
@stub.function()
@web_endpoint()
def public_endpoint(data: dict):
    return model(data)  # Anyone can call

# VULNERABLE: No input validation
@stub.function()
@web_endpoint(method="POST")
def unvalidated_endpoint(request: dict):
    return model(request["prompt"])  # No limits

# VULNERABLE: Return sensitive data
@stub.function(secrets=[modal.Secret.from_name("api-keys")])
@web_endpoint()
def leaky_endpoint():
    return {
        "api_key": os.environ["API_KEY"],  # Exposed
        "result": "data"
    }

# VULNERABLE: No rate limiting
@stub.function()
@web_endpoint(method="POST")
def unlimited_endpoint(request: PredictionRequest):
    return process(request)  # DoS vector
```

**Why**: Unprotected endpoints enable unauthorized access, abuse of GPU resources, and denial of service attacks.

**Refs**: OWASP A01:2025, CWE-306, CWE-770

---

## Scheduled Function Security

### Rule: Secure Modal Scheduled Functions

**Level**: `strict`

**When**: Using Modal schedules and cron jobs.

**Do**:
```python
import modal
from datetime import datetime
import logging

stub = modal.Stub("secure-scheduled")

logger = logging.getLogger(__name__)

# Safe: Scheduled function with validation and logging
@stub.function(
    schedule=modal.Cron("0 * * * *"),  # Hourly
    secrets=[modal.Secret.from_name("db-credentials")],
    timeout=1800,  # 30 minute timeout
    retries=1
)
def secure_scheduled_job():
    start_time = datetime.utcnow()
    logger.info(f"Job started at {start_time}")

    try:
        # Perform job with resource awareness
        result = process_data()

        # Log completion (no sensitive data)
        logger.info(f"Job completed: {result['count']} items processed")

        return {
            "status": "success",
            "count": result["count"],
            "duration": (datetime.utcnow() - start_time).seconds
        }

    except Exception as e:
        # Log error without sensitive details
        logger.error(f"Job failed: {type(e).__name__}")
        raise

# Safe: Scheduled function with concurrency control
@stub.function(
    schedule=modal.Period(hours=1),
    timeout=600,
    concurrency_limit=1  # Only one instance at a time
)
def singleton_job():
    # Ensure no overlap
    pass

# Safe: Manual trigger with validation
@stub.function()
def manual_trigger(job_name: str, params: dict):
    # Validate job name
    allowed_jobs = {"sync", "cleanup", "backup"}
    if job_name not in allowed_jobs:
        raise ValueError(f"Unknown job: {job_name}")

    # Validate params
    if params.get("force") and not params.get("confirmed"):
        raise ValueError("Force requires confirmation")

    # Execute job
    return execute_job(job_name, params)
```

**Don't**:
```python
# VULNERABLE: No timeout
@stub.function(schedule=modal.Cron("* * * * *"))
def no_timeout_job():
    process_forever()  # Can run indefinitely

# VULNERABLE: Log sensitive data
@stub.function(schedule=modal.Period(hours=1))
def logging_secrets():
    api_key = os.environ["API_KEY"]
    print(f"Using key: {api_key}")  # In logs

# VULNERABLE: No concurrency control
@stub.function(schedule=modal.Cron("*/5 * * * *"))
def overlapping_job():
    long_running_task()  # Multiple instances pile up

# VULNERABLE: Arbitrary job execution
@stub.function()
def run_any_job(job_name: str):
    return globals()[job_name]()  # Code injection
```

**Why**: Scheduled functions can accumulate costs, leak secrets through logs, or be manipulated to execute unintended code.

**Refs**: CWE-400, CWE-532, CWE-94

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure Modal function configuration | strict | CWE-400, CWE-502 |
| Secure Modal secrets handling | strict | CWE-798, CWE-532 |
| Harden Modal container images | strict | CWE-250, CWE-269 |
| Secure Modal web endpoints | strict | OWASP A01:2025, CWE-306 |
| Secure Modal scheduled functions | strict | CWE-400, CWE-532 |

---

## Version History

- **v1.0.0** - Initial Modal security rules
