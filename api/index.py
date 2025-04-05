# api/index.py
import os
from flask import Flask, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    print(f"[{datetime.now(timezone.utc).isoformat()}] Flask handler invoked for path: /{path}")

    # Optional: Check if env var reading works at a basic level
    key_var = 'THREAT_API_KEY'
    api_key_present = key_var in os.environ
    print(f"{key_var} is present in environment: {api_key_present}")

    return jsonify({
        "message": "Python API OK",
        "key_present": api_key_present
    }), 200

# Lambda-compatible handler for Vercel
def handler(event, context):
    return app(event, context)