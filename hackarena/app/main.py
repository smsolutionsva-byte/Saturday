import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load the environment configurations from your .env file
load_dotenv()

from app.agents.orchestrator import route_incident

# CRITICAL: This must be named exactly 'app' so uvicorn can find it
app = FastAPI(title="SentinelAI Backend")

# Enable communication between your Streamlit dashboard and your FastAPI endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "online", "system": "SentinelAI Multi-Agent Core"}

# The catch-all wildcard route interceptor
@app.post("/{catchall:path}")
async def catch_all_post_routes(catchall: str, request: Request):
    """
    Intercepts and routes incoming UI requests to the orchestrator layer.
    """
    print(f"\n[SENTINEL CORE] Incoming request captured on path: /{catchall}")
    
    payload = await request.json()
    print(f"[SENTINEL CORE] Extracted Payload: {payload}\n")
    
    result = route_incident(payload)
    return result