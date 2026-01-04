#!/usr/bin/env python3
"""
Bootstrap script for starting a local VeilNet devnet node.
"""
import uvicorn
import os
import sys

def main():
    """Starts the Uvicorn server for the VeilNet node."""
    # This ensures that the project root is on the Python path,
    # allowing absolute imports like `from core.identity import ...`
    # when running this script directly.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    uvicorn.run(
        "node.server:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
        app_dir=project_root  # Set the app directory to the project root
    )

if __name__ == "__main__":
    main()
