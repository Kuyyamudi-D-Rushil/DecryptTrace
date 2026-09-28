# Air-Gap Deployment Checklist

This document tracks the steps required to achieve a fully offline, reproducible build of DecryptTrace for high-security environments. An air-gapped build must not rely on the internet at build time or runtime.

## Status Summary

* **Vendoring pip wheels**: NOT STARTED
* **Pinning and hashing dependencies**: NOT STARTED
* **Localizing Docker base images**: NOT STARTED
* **Offline build verification**: NOT STARTED

---

## Detailed Checklist

### 1. Dependency Pinning and Integrity
- [ ] **NOT STARTED**: Pin exact versions for all dependencies (e.g., `requirements.txt` generated via `pip-compile` or Poetry/uv lockfiles). Currently, `requirements.txt` contains loose bounds (e.g., `pydantic>=2`) and unpinned packages.
- [ ] **NOT STARTED**: Include cryptographic hashes for all dependencies (`--hash=sha256:...`). The current `requirements.txt` does not include hashes to guarantee integrity against tampering.

### 2. Offline Dependency Availability
- [ ] **NOT STARTED**: Vendor all required Python packages (wheels/sdists) into the repository or a companion tarball. Currently, the `Dockerfile` uses `pip install` which pulls directly from the public PyPI network.
- [ ] **NOT STARTED**: Vendor system-level dependencies. If `liboqs-python` or other libraries require system packages (like `build-essential`, `cmake`, or C libraries) during the build, their `.deb`/source files must also be provided locally.

### 3. Container Images
- [ ] **NOT STARTED**: Save and transfer Docker base images (`python:3.12-slim`) as offline tarballs (`docker save`), or configure the build to pull from a private, air-gapped internal registry rather than Docker Hub.

### 4. Build Configuration
- [ ] **NOT STARTED**: Update the `Dockerfile` to use the localized wheels and base images instead of fetching from the internet. Currently, `RUN pip install --no-cache-dir fastapi uvicorn[standard] pydantic` will fail without a network.

### 5. Verification
- [ ] **NOT STARTED**: Successfully execute the entire build process (e.g., `docker build --network none ...`) to guarantee no hidden network calls exist.
- [ ] **NOT STARTED**: Verify the built container starts and passes health checks in a fully isolated environment.
