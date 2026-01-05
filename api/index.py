import sys
import os

# This allows the serverless function to find the 'node' module by adding the project root to the Python path.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the FastAPI app instance from your existing server file
from node.server import app

# Vercel's Python runtime will automatically detect and serve this 'app' object.
# No handler function or wrapper like Mangum is needed.
