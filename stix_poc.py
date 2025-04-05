# stix_poc.py
import os
from flask import Flask, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def handler_route(path):
    print(f"[{datetime.now(timezone.utc).isoformat()}] Flask route hit at path: /{path}")
    api_key_present = 'THREAT_API_KEY' in os.environ
    return jsonify({
        "message": "Minimal Flask API OK",
        "key_present": api_key_present
    })

# Convert WSGI app to AWS Lambda-style handler for Vercel
def handler(event, context):
    from werkzeug.wrappers import Response
    from io import BytesIO
    from urllib.parse import urlencode
    from werkzeug.test import EnvironBuilder

    # Extract request data
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    headers = event.get("headers") or {}
    query = event.get("queryStringParameters") or {}
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64
        body = base64.b64decode(body)

    # Build WSGI environment
    builder = EnvironBuilder(
        method=method,
        path=path,
        headers=headers,
        query_string=urlencode(query),
        data=body,
    )
    env = builder.get_environ()

    # Get Flask response
    response: Response = app.full_dispatch_request()
    return {
        "statusCode": response.status_code,
        "headers": dict(response.headers),
        "body": response.get_data(as_text=True),
    }
