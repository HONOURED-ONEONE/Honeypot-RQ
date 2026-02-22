#!/usr/bin/env python3
import sys
import os

print("Running preflight import check...")
try:
    # Set dummy env vars to avoid KeyErrors during config load if any
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
    
    import app.main
    print("Import app.main: OK")
    
    import app.callback.outbox
    print("Import app.callback.outbox: OK")
    
    print("Preflight check passed.")
    sys.exit(0)
except Exception as e:
    print(f"Preflight check FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
