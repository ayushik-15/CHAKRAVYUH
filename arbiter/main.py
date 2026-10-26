import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Explicitly allow Vite's local dev servers to resolve the 403 CORS issue
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Changed endpoint to match the frontend request (/ws/events)
@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        await websocket.send_text(json.dumps({
            "type": "info",
            "plane": "System Initialized",
            "payload": "Arbiter Hub online. Commencing Commit-Reveal Evaluation Protocol."
        }))
        
        step = 0
        while True:
            await asyncio.sleep(4)
            if step % 3 == 0:
                event = {"type": "attack", "plane": "Red Plane", "payload": "Commit: Adversarial prompt injected into target model context."}
            elif step % 3 == 1:
                event = {"type": "defense", "plane": "Blue Plane", "payload": "Reveal: Semantic guardrails triggered. Attack payload neutralized."}
            else:
                event = {"type": "info", "plane": "Arbiter Verdict", "payload": "Evaluation Cycle Complete. Hash successfully appended to Merkle Log."}
            
            await websocket.send_text(json.dumps(event))
            step += 1

    except WebSocketDisconnect:
        print("Frontend dashboard disconnected from Arbiter Hub.")