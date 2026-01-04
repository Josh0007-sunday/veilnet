import sys
import os

# This allows the serverless function to find the main app by adding the project root to the Python path.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from node.server import app
from mangum import Mangum

# This handler wraps the FastAPI app, making it compatible with Netlify's (AWS Lambda) environment.
handler = Mangum(app)
