# DecryptTrace — Environment Status Diagnostic

## System Information
- **OS Platform:** Windows 11 (AMD64 / x86_64)
- **Python Version:** 3.12.0
- **Python Executable:** `C:\Users\Rushil D K\.gemini\antigravity\scratch\DecryptTrace\venv\Scripts\python.exe`
- **Pip Version:** 23.2.1
- **Virtual Environment:** `C:\Users\Rushil D K\.gemini\antigravity\scratch\DecryptTrace\venv`

## Build Tools & Compilers
- **CMake Version:** 4.4.3 (`C:\Program Files\CMake\bin\cmake.exe`)
- **Compiler Version:** MSVC 19.51.36246 for x64 (`Visual Studio Build Tools 2026`)
- **Windows SDK:** 10.0.26100.0 (`rc.exe` and Universal CRT verified)
- **Toolchain Status:** Operational and verified. Successfully compiled `liboqs` C library using native Visual Studio 18 2026 generator.

## PyMuPDF Status
- **Package:** `pymupdf`
- **Installed Version:** 1.28.2
- **Import Standard:** `import pymupdf` (Verified)
- **Status:** Functional and healthy.

## liboqs & liboqs-python Status
- **liboqs Version:** 0.16.0
- **liboqs-python Version:** 0.16.0
- **Shared Library Location:** `C:\Users\Rushil D K\_oqs\bin\oqs.dll`
- **Import Status:** `import oqs` succeeds cleanly.
- **Available ML-KEM Mechanisms:**
  - `ML-KEM-512`: Available
  - `ML-KEM-768`: Available (Verified)
  - `ML-KEM-1024`: Available (Verified)
  - *(Also enabled: Kyber, Classic-McEliece, HQC, NTRU, FrodoKEM, sntrup761)*
- **Available ML-DSA Mechanisms:**
  - `ML-DSA-44`: Available
  - `ML-DSA-65`: Available (Verified)
  - `ML-DSA-87`: Available (Verified)
  - *(Also enabled: Falcon, MAYO, CROSS, Rainbow/OV, SNOVA, MQOM2, SLH-DSA)*

## Complete Import Test Results (`check_imports.py`)

| Package | Status | Version | Import Result | Error |
| :--- | :--- | :--- | :--- | :--- |
| `fastapi` | INSTALLED | 0.141.1 | SUCCESS | None |
| `uvicorn[standard]` | INSTALLED | 0.53.0 | SUCCESS | None |
| `pydantic>=2` | INSTALLED | 2.13.5 | SUCCESS | None |
| `sqlalchemy>=2` | INSTALLED | 2.0.54 | SUCCESS | None |
| `liboqs-python` | INSTALLED | 0.16.0 | SUCCESS | None |
| `cryptography` | INSTALLED | 50.0.1 | SUCCESS | None |
| `pymupdf` | INSTALLED | 1.28.2 | SUCCESS | None |
| `pikepdf` | INSTALLED | 10.13.0.post1 | SUCCESS | None |
| `pillow` | INSTALLED | 12.3.0 | SUCCESS | None |
| `numpy` | INSTALLED | 2.5.3 | SUCCESS | None |
| `scipy` | INSTALLED | 1.18.1 | SUCCESS | None |
| `pywavelets` | INSTALLED | 1.10.0 | SUCCESS | None |
| `opencv-python` | INSTALLED | 5.0.0.93 | SUCCESS | None |
| `scikit-image` | INSTALLED | 0.26.0 | SUCCESS | None |
| `streamlit` | INSTALLED | 1.64.0 | SUCCESS | None |
| `pytest` | INSTALLED | 9.1.1 | SUCCESS | None |
| `pytest-benchmark` | INSTALLED | 5.3.0 | SUCCESS | None |
| `hypothesis` | INSTALLED | 6.168.0 | SUCCESS | None |
| `ruff` | INSTALLED | 0.16.8 | SUCCESS | None |
| `mypy` | INSTALLED | 2.3.1 | SUCCESS | None |

## Overall Verification Summary
- **Total Packages:** 20
- **Import Success:** 20/20 (100%)
- **Import Failures:** 0
- **Remaining Environment Blockers:** None.
