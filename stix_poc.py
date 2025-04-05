# stix_poc.py
import os
from flask import Flask, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handler_route(path):
    print(f"[{datetime.now(timezone.utc).isoformat()}] Minimal Python handler invoked for path: /{path}")

    # Optional: Check if env var reading works
    key_var = 'THREAT_API_KEY'
    api_key_present = key_var in os.environ
    print(f"{key_var} is present in environment: {api_key_present}")

    return jsonify({
        "message": "Minimal Python API OK",
        "key_present": api_key_present
    }), 200

# Vercel expects a 'handler' object to expose
handler = app
