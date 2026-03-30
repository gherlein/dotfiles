# MLflow Security Rules

Security rules for MLflow experiment tracking and model registry in Claude Code.

## Prerequisites

- `rules/_core/ai-security.md` - AI/ML security foundations
- `rules/languages/python/CLAUDE.md` - Python security

---

## Model Registry Security

### Rule: Secure Model Registration and Loading

**Level**: `strict`

**When**: Registering and loading models from MLflow registry.

**Do**:
```python
import mlflow
from mlflow.tracking import MlflowClient
import hashlib
import os

# Safe: Configure MLflow with authentication
mlflow.set_tracking_uri(os.environ["MLFLOW_TRACKING_URI"])

# Safe: Register model with metadata and signatures
from mlflow.models.signature import infer_signature

def register_secure_model(
    model,
    model_name: str,
    input_example,
    registered_model_name: str
):
    # Infer and validate signature
    signature = infer_signature(
        input_example,
        model.predict(input_example)
    )

    # Log model with security metadata
    with mlflow.start_run():
        mlflow.log_params({
            "model_type": type(model).__name__,
            "safe_serialization": "true"
        })

        # Use safe serialization formats
        model_info = mlflow.sklearn.log_model(
            model,
            artifact_path="model",
            signature=signature,
            input_example=input_example,
            registered_model_name=registered_model_name,
            # Additional metadata
            metadata={
                "security_reviewed": "true",
                "version": "1.0"
            }
        )

    return model_info

# Safe: Load model with verification
def load_verified_model(model_uri: str, expected_hash: str = None):
    # Validate model URI format
    if not model_uri.startswith(("models:/", "runs:/")):
        raise ValueError("Invalid model URI format")

    # Load model info first
    client = MlflowClient()

    if model_uri.startswith("models:/"):
        parts = model_uri.replace("models:/", "").split("/")
        model_name = parts[0]
        version = parts[1] if len(parts) > 1 else "latest"

        # Get model version details
        if version == "latest":
            versions = client.get_latest_versions(model_name)
            if not versions:
                raise ValueError(f"No versions found for {model_name}")
            model_version = versions[0]
        else:
            model_version = client.get_model_version(model_name, version)

        # Check model stage/tags for approval
        if model_version.current_stage not in ["Production", "Staging"]:
            raise ValueError("Model not approved for use")

    # Load the model
    model = mlflow.pyfunc.load_model(model_uri)

    return model

# Safe: Model stage transitions with approval
def promote_model(
    model_name: str,
    version: str,
    target_stage: str,
    approver: str
):
    client = MlflowClient()

    # Validate target stage
    valid_stages = ["Staging", "Production", "Archived"]
    if target_stage not in valid_stages:
        raise ValueError(f"Invalid stage: {target_stage}")

    # Add approval tag before transition
    client.set_model_version_tag(
        model_name, version,
        "approved_by", approver
    )
    client.set_model_version_tag(
        model_name, version,
        "approval_time", str(int(time.time()))
    )

    # Transition with archival of previous version
    client.transition_model_version_stage(
        model_name, version, target_stage,
        archive_existing_versions=True
    )
```

**Don't**:
```python
# VULNERABLE: Load any model URI
model = mlflow.pyfunc.load_model(user_provided_uri)

# VULNERABLE: No stage validation
def deploy_model(model_name: str):
    model = mlflow.pyfunc.load_model(f"models:/{model_name}/latest")
    # Could be unapproved model

# VULNERABLE: Direct production deployment
client.transition_model_version_stage(
    model_name, version, "Production"
    # No approval process
)

# VULNERABLE: Pickle serialization
import pickle
with mlflow.start_run():
    pickle.dump(model, open("model.pkl", "wb"))
    mlflow.log_artifact("model.pkl")  # RCE risk
```

**Why**: Uncontrolled model loading enables supply chain attacks through poisoned models. No approval process allows untested models in production.

**Refs**: OWASP LLM05, CWE-502, MITRE ATLAS AML.T0010

---

## Experiment Tracking Security

### Rule: Protect Experiment Data and Parameters

**Level**: `strict`

**When**: Logging experiments and runs.

**Do**:
```python
import mlflow
import os
from typing import Any

# Safe: Sanitize logged parameters
SENSITIVE_PARAMS = [
    "password", "secret", "key", "token", "credential", "api_key"
]

def safe_log_params(params: dict[str, Any]):
    """Log parameters with sensitive data filtering"""
    sanitized = {}

    for key, value in params.items():
        # Check for sensitive parameter names
        if any(s in key.lower() for s in SENSITIVE_PARAMS):
            sanitized[key] = "[REDACTED]"
        else:
            # Convert to string and limit length
            str_value = str(value)[:250]
            sanitized[key] = str_value

    mlflow.log_params(sanitized)

# Safe: Secure experiment configuration
def create_secure_experiment(name: str, artifact_location: str):
    client = mlflow.tracking.MlflowClient()

    # Validate artifact location
    allowed_prefixes = ["s3://mlflow-artifacts/", "gs://mlflow-artifacts/"]
    if not any(artifact_location.startswith(p) for p in allowed_prefixes):
        raise ValueError("Invalid artifact location")

    # Create with secure defaults
    experiment_id = client.create_experiment(
        name=name,
        artifact_location=artifact_location,
        tags={
            "security_level": "standard",
            "data_classification": "internal"
        }
    )

    return experiment_id

# Safe: Log artifacts with validation
def safe_log_artifacts(local_dir: str, artifact_path: str = None):
    """Log artifacts with size and type validation"""
    from pathlib import Path

    local_path = Path(local_dir)

    # Validate path
    if not local_path.exists():
        raise ValueError("Path does not exist")

    if not local_path.is_dir():
        raise ValueError("Path must be a directory")

    # Check file sizes and types
    max_file_size = 100 * 1024 * 1024  # 100MB
    allowed_extensions = {
        ".json", ".yaml", ".yml", ".txt", ".csv",
        ".png", ".jpg", ".html", ".md"
    }

    for file_path in local_path.rglob("*"):
        if file_path.is_file():
            # Size check
            if file_path.stat().st_size > max_file_size:
                raise ValueError(f"File too large: {file_path}")

            # Extension check
            if file_path.suffix.lower() not in allowed_extensions:
                raise ValueError(f"File type not allowed: {file_path}")

            # Check for sensitive content
            if file_path.suffix in [".json", ".yaml", ".yml", ".txt"]:
                content = file_path.read_text()
                for pattern in SENSITIVE_PARAMS:
                    if pattern in content.lower():
                        raise ValueError(f"Sensitive data in: {file_path}")

    mlflow.log_artifacts(local_dir, artifact_path)

# Safe: Secure run context
with mlflow.start_run(run_name="secure_training"):
    # Log safe parameters
    safe_log_params({
        "learning_rate": 0.01,
        "epochs": 100,
        "model_type": "classifier"
    })

    # Train model...

    # Log metrics (public data)
    mlflow.log_metrics({
        "accuracy": 0.95,
        "loss": 0.05
    })

    # Log artifacts with validation
    safe_log_artifacts("./outputs")
```

**Don't**:
```python
# VULNERABLE: Log sensitive parameters
mlflow.log_params({
    "api_key": os.environ["API_KEY"],  # Exposed in UI
    "password": "secret123"
})

# VULNERABLE: Log arbitrary files
mlflow.log_artifacts("/path/to/anything")  # Could include secrets

# VULNERABLE: Log unvalidated user input
mlflow.log_param("user_query", user_input)  # Injection risk

# VULNERABLE: Public artifact location
client.create_experiment(
    name="experiment",
    artifact_location="s3://public-bucket/"  # Publicly accessible
)
```

**Why**: Logged parameters and artifacts are visible in the MLflow UI and storage, making sensitive data exposure a significant risk.

**Refs**: CWE-200, CWE-532, OWASP A01:2025

---

## Artifact Security

### Rule: Secure Artifact Storage and Access

**Level**: `strict`

**When**: Storing and retrieving MLflow artifacts.

**Do**:
```python
import mlflow
import os
from pathlib import Path

# Safe: Configure secure artifact storage
"""
# Environment configuration for S3
export MLFLOW_S3_ENDPOINT_URL=https://s3.amazonaws.com
export AWS_ACCESS_KEY_ID=<from-secrets-manager>
export AWS_SECRET_ACCESS_KEY=<from-secrets-manager>

# Use server-side encryption
export MLFLOW_S3_UPLOAD_EXTRA_ARGS='{"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": "alias/mlflow-key"}'
"""

# Safe: Download artifacts with validation
def download_verified_artifact(
    run_id: str,
    artifact_path: str,
    dst_path: str
):
    client = mlflow.tracking.MlflowClient()

    # Validate artifact path (no traversal)
    if ".." in artifact_path or artifact_path.startswith("/"):
        raise ValueError("Invalid artifact path")

    # Validate destination
    dst = Path(dst_path).resolve()
    allowed_base = Path("/app/artifacts").resolve()

    if not str(dst).startswith(str(allowed_base)):
        raise ValueError("Destination outside allowed directory")

    # Download
    local_path = client.download_artifacts(
        run_id, artifact_path, dst_path
    )

    # Verify downloaded files
    for file_path in Path(local_path).rglob("*"):
        if file_path.is_file():
            # Check for executable files
            if file_path.suffix in [".exe", ".sh", ".bat", ".py"]:
                # Mark as non-executable
                os.chmod(file_path, 0o644)

    return local_path

# Safe: Artifact access control via MLflow server
"""
# mlflow server configuration
mlflow server \
    --backend-store-uri postgresql://... \
    --default-artifact-root s3://mlflow-artifacts/ \
    --host 127.0.0.1 \
    --port 5000 \
    --app-name basic-auth  # Require authentication
"""

# Safe: Signed URLs for artifact access
import boto3
from botocore.config import Config

def get_signed_artifact_url(
    bucket: str,
    key: str,
    expiration: int = 3600
) -> str:
    """Generate time-limited signed URL for artifact access"""
    s3_client = boto3.client(
        "s3",
        config=Config(signature_version="s3v4")
    )

    url = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expiration
    )

    return url
```

**Don't**:
```python
# VULNERABLE: Unencrypted artifact storage
"""
export MLFLOW_ARTIFACT_ROOT=s3://public-bucket/
# No encryption configured
"""

# VULNERABLE: Path traversal in downloads
def download_artifact(run_id: str, path: str):
    return client.download_artifacts(run_id, path, "/tmp")
    # User controls path

# VULNERABLE: Execute downloaded artifacts
artifact_path = client.download_artifacts(run_id, "script.py")
exec(open(artifact_path).read())  # RCE

# VULNERABLE: Public artifact access
"""
mlflow server \
    --host 0.0.0.0 \
    # No authentication
"""
```

**Why**: Artifacts may contain sensitive model weights, training data, or configuration. Improper access control enables data theft.

**Refs**: CWE-22, CWE-311, OWASP A01:2025

---

## Server Security

### Rule: Secure MLflow Server Configuration

**Level**: `strict`

**When**: Deploying MLflow tracking server.

**Do**:
```python
# Safe: MLflow server with authentication
"""
# Start with authentication
mlflow server \
    --backend-store-uri postgresql://user:password@host/mlflow \
    --default-artifact-root s3://secure-bucket/artifacts \
    --host 127.0.0.1 \
    --port 5000 \
    --app-name basic-auth \
    --gunicorn-opts "--timeout 60 --workers 4"
"""

# Safe: Reverse proxy with TLS and auth
"""
# nginx.conf
server {
    listen 443 ssl;
    server_name mlflow.example.com;

    ssl_certificate /etc/ssl/certs/mlflow.crt;
    ssl_certificate_key /etc/ssl/private/mlflow.key;

    # Authentication
    auth_basic "MLflow";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header Content-Security-Policy "default-src 'self'";

    # Rate limiting
    limit_req zone=mlflow burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Request size limits
        client_max_body_size 100M;
    }
}
"""

# Safe: Database connection with SSL
import os

db_uri = (
    f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASS']}"
    f"@{os.environ['DB_HOST']}/{os.environ['DB_NAME']}"
    f"?sslmode=require"
)

# Safe: Kubernetes deployment with security
"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mlflow-server
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
      - name: mlflow
        image: mlflow-server:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          limits:
            memory: "2Gi"
            cpu: "1"
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mlflow-secrets
              key: db-password
        ports:
        - containerPort: 5000
"""
```

**Don't**:
```python
# VULNERABLE: Public server without auth
"""
mlflow server \
    --host 0.0.0.0 \
    --port 5000
    # No authentication
"""

# VULNERABLE: Hardcoded credentials
"""
mlflow server \
    --backend-store-uri postgresql://admin:password123@host/db
"""

# VULNERABLE: No TLS
"""
mlflow server \
    --host 0.0.0.0
    # Plain HTTP
"""

# VULNERABLE: SQLite in production
"""
mlflow server \
    --backend-store-uri sqlite:///mlflow.db
    # Not suitable for multi-user production
"""
```

**Why**: Exposed MLflow servers allow unauthorized access to models, experiments, and potentially sensitive training data.

**Refs**: OWASP A01:2025, CWE-306, CWE-319

---

## Quick Reference

| Rule | Level | CWE/OWASP |
|------|-------|-----------|
| Secure model registration and loading | strict | OWASP LLM05, CWE-502 |
| Protect experiment data and parameters | strict | CWE-200, CWE-532 |
| Secure artifact storage and access | strict | CWE-22, CWE-311 |
| Secure MLflow server configuration | strict | OWASP A01:2025, CWE-306 |

---

## Version History

- **v1.0.0** - Initial MLflow security rules
