# api/index.py
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timezone

app = FastAPI()

@app.get("/{path:path}")
async def catch_all(path: str = "", request: Request = None):
    print(f"[{datetime.now(timezone.utc).isoformat()}] FastAPI handler invoked for path: /{path}")

    # Optional: Check if env var reading works at a basic level
    key_var = 'THREAT_API_KEY'
    api_key_present = key_var in os.environ
    print(f"{key_var} is present in environment: {api_key_present}")

    return {
        "message": "Python API OK",
        "key_present": api_key_present
    }

# For local development
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)