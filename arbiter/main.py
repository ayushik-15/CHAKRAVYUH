"""CHAKRAVYUH - Arbiter Service"""
from fastapi import FastAPI

app = FastAPI(title="CHAKRAVYUH Arbiter")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "arbiter", "version": "0.1.0"}
