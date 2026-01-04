"""
VeilNet Node Server
"""
from fastapi import FastAPI
from .routes import router as api_router

app = FastAPI(
    title="VeilNet Node",
    description="A single-node implementation of the VeilNet protocol.",
    version="0.1.0"
)

# Include API routes
app.include_router(api_router, prefix="/api")

@app.get("/", tags=["Status"])
async def root():
    """Root endpoint to check node status."""
    return {"status": "ok", "message": "VeilNet node is running"}
