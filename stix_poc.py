# api/stix_poc.py (TEMPORARY MINIMAL TEST)
import os
from flask import Flask, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handler(path):
    # This print statement is crucial - check Vercel logs for it
    print(f"[{datetime.now(timezone.utc).isoformat()}] Minimal Python handler invoked for path: /{path}")

    # Optional: Check if env var reading works at a basic level
    key_var = 'THREAT_API_KEY' # The key we expect
    api_key_present = key_var in os.environ
    print(f"{key_var} is present in environment: {api_key_present}")

    # Return a simple success message
    return jsonify({"message": "Minimal Python API OK", "key_present": api_key_present}), 200

# No app.run() needed for Vercel