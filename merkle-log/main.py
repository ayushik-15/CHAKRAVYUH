"""CHAKRAVYUH - Merkle Log Service"""
from fastapi import FastAPI

app = FastAPI(title="CHAKRAVYUH Merkle Log")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "merkle-log"}
