# Docker Air-Gap Verification Procedure

This procedure verifies that the Phase 1 development container runs in an air-gapped configuration (`network_mode: "none"`) and that the API functions without external network access.

## Procedure

1. **Build and start the container:**
   ```bash
   docker compose build
   docker compose up -d
   ```

2. **Verify the process is running:**
   ```bash
   docker compose ps
   # Ensure airgap-service is listed as "Up"
   ```

3. **Execute an internal HTTP health request from inside the container:**
   Since the container lacks external network access and published ports, you must enter the container to test the API.
   ```bash
   docker compose exec airgap-service python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())"
   ```
   **Expected Output:** `{"status":"ok","air_gap_mode":true}`

4. **Verify there is no network connectivity:**
   Attempt to access the public internet from inside the container:
   ```bash
   docker compose exec airgap-service python -c "import urllib.request; urllib.request.urlopen('http://93.184.216.34', timeout=3)"
   ```
   **Expected Output:** Network unreachable or connection timeout error.

## Limitations
Fully offline dependency vendoring is not yet implemented in Phase 1. The `Dockerfile` requires internet access during the `docker compose build` phase to download Python packages. This is a known limitation of the Phase 1 skeleton rather than a completely reproducible offline artifact. True offline build capabilities will be required before production deployment.
