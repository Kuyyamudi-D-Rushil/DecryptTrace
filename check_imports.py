import importlib
import importlib.metadata
import sys

# Mapping from requirements.txt package name to python import name
PACKAGES = [
    ("fastapi", "fastapi"),
    ("uvicorn[standard]", "uvicorn"),
    ("pydantic>=2", "pydantic"),
    ("sqlalchemy>=2", "sqlalchemy"),
    ("liboqs-python", "oqs"),
    ("cryptography", "cryptography"),
    ("pymupdf", "pymupdf"),
    ("pikepdf", "pikepdf"),
    ("pillow", "PIL"),
    ("numpy", "numpy"),
    ("scipy", "scipy"),
    ("pywavelets", "pywt"),
    ("opencv-python", "cv2"),
    ("scikit-image", "skimage"),
    ("streamlit", "streamlit"),
    ("pytest", "pytest"),
    ("pytest-benchmark", "pytest_benchmark"),
    ("hypothesis", "hypothesis"),
    ("ruff", "ruff"),
    ("mypy", "mypy"),
]

def get_installed_version(pkg_name):
    # Strip extras/specifiers
    clean_name = pkg_name.split("[")[0].split(">")[0].split("<")[0].split("=")[0]
    try:
        return importlib.metadata.version(clean_name)
    except importlib.metadata.PackageNotFoundError:
        return "Unknown"

all_passed = True

print(f"{'PACKAGE':<20} | {'STATUS':<10} | {'VERSION':<12} | {'IMPORT RESULT':<15} | {'ERROR'}")
print("-" * 80)

for pkg_req, mod_name in PACKAGES:
    version = get_installed_version(pkg_req)
    status = "INSTALLED" if version != "Unknown" else "NOT INSTALLED"
    import_result = "SUCCESS"
    err_msg = ""
    
    try:
        # Avoid hanging on automatic build attempt in liboqs-python
        if mod_name == "oqs":
            import os
            # If liboqs C library is not installed, avoid interactive/blocking prompts
            os.environ["OQS_AUTODOWNLOAD"] = "0"
        importlib.import_module(mod_name)
    except (ImportError, RuntimeError) as e:
        import_result = "FAILED"
        err_msg = str(e)
        all_passed = False
    except SystemExit as e:
        import_result = "FAILED"
        err_msg = f"SystemExit({e})"
        all_passed = False
        
    print(f"{pkg_req:<20} | {status:<10} | {version:<12} | {import_result:<15} | {err_msg}")

if not all_passed:
    sys.exit(1)
