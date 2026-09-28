import sys
print("Starting import validation test...")

try:
    import app
    print("Successfully imported app")
    
    from app.state import AppState
    print("Successfully imported AppState")
    
    from app.forensics.matcher import match_artifact
    print("Successfully imported match_artifact")
    
    from app.evidence.package import EvidencePackage
    print("Successfully imported EvidencePackage")
    
    print("All imports successful! The package is correctly installed/configured.")
    sys.exit(0)
except ModuleNotFoundError as e:
    print(f"FAILED: {e}")
    sys.exit(1)
except Exception as e:
    print(f"FAILED with unexpected error: {e}")
    sys.exit(1)
