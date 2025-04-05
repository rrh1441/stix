# api/index.py (in 'stix' repo root)

import os
import requests
import json
import traceback
import uuid # Needed for bundle ID
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

# --- Import local modules ---
try:
    # Assumes stix_mapper.py is in the same directory (project root)
    from stix_mapper import map_flashpoint_vuln_to_stix, TLP_WHITE_DEFINITION
except ImportError as e:
    print(f"CRITICAL ERROR: Cannot import stix_mapper: {e}. Ensure stix_mapper.py is in the project root.")
    # Define dummy function so FastAPI app can load, but endpoint will fail clearly
    def map_flashpoint_vuln_to_stix(data): raise RuntimeError("stix_mapper not found")
    # Define a placeholder TLP_WHITE_DEFINITION dict if import fails
    TLP_WHITE_DEFINITION_DICT = {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z", "definition_type": "statement",
        "definition": { "statement": "TLP:WHITE" }
    }
else:
    # If import succeeded, create a dictionary version for JSON serialization
    # Note: Accessing internal '_properties' is not ideal but works for simple cases.
    # A better way might be needed if the stix2 object is complex.
    try:
        TLP_WHITE_DEFINITION_DICT = TLP_WHITE_DEFINITION.serialize()
    except Exception as serialize_err:
         print(f"Warning: Could not serialize TLP_WHITE_DEFINITION object: {serialize_err}")
         # Fallback to manual dict
         TLP_WHITE_DEFINITION_DICT = {
            "type": "marking-definition", "spec_version": "2.1",
            "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "statement",
            "definition": { "statement": "TLP:WHITE" }
         }


# --- Environment Variables ---
API_KEY = os.environ.get('THREAT_API_KEY')
VULN_API_URL = os.environ.get('FP_VULN_API_URL')
try:
    API_PAGE_SIZE = int(os.environ.get('FP_API_PAGE_SIZE', 500))
except (ValueError, TypeError):
    API_PAGE_SIZE = 500

REQUEST_TIMEOUT_S = 60 # Timeout per page fetch

# --- FastAPI App Setup ---
app = FastAPI(title="STIX Generator API")

# --- CORS Configuration ---
origins = [
    "https://threat-dashboard.vercel.app", # Frontend production URL
    # Add preview URLs like "https://threat-dashboard-*.vercel.app" if needed
    "http://localhost:3000", # For local frontend development
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET"], # Only allow GET for the stix endpoint
    allow_headers=["*"],
)
# --- End CORS ---

# --- API Helper Function with Pagination ---
# Note: Using synchronous 'requests' here. If many users hit this endpoint
# concurrently, using 'httpx' async client would be better for performance.
def get_all_flashpoint_vulnerabilities(params: dict):
    """Queries the Flashpoint Vulnerability API with pagination (synchronous)."""
    if not API_KEY:
        print("Error: THREAT_API_KEY environment variable not set.")
        raise HTTPException(status_code=500, detail="Server configuration error: Missing API Key.")
    if not VULN_API_URL:
        print("Error: FP_VULN_API_URL environment variable not set.")
        raise HTTPException(status_code=500, detail="Server configuration error: Missing API URL.")

    headers = {"Authorization": f"Bearer {API_KEY}", "Accept": "application/json"}
    api_base_url = VULN_API_URL.rstrip('/')
    api_url = f"{api_base_url}/vulnerabilities"
    all_vulnerabilities = []
    current_page = 0
    page_size = API_PAGE_SIZE
    total_hits = None
    max_pages = 100

    print(f"Starting vulnerability fetch. Base URL: {api_url}, Params: {params}")

    while current_page < max_pages:
        page_params = params.copy()
        page_params['from'] = current_page * page_size
        page_params['size'] = page_size
        print(f"Querying page {current_page + 1} (from={page_params['from']}, size={page_params['size']})...")

        try:
            response = requests.get(api_url, headers=headers, params=page_params, timeout=REQUEST_TIMEOUT_S)
            print(f"-> Request URL: {response.url} -> Status: {response.status_code}")
            response.raise_for_status()
            data = response.json()

            page_items = data.get('results', data.get('data', []))
            if not isinstance(page_items, list): page_items = []

            all_vulnerabilities.extend(page_items)
            num_returned = len(page_items)
            print(f"-> Got {num_returned} results on this page.")

            if total_hits is None: # Parse total only once
                raw_total = data.get('total_hits', data.get('total', None)); total_hits_val = None
                if isinstance(raw_total, dict): total_hits_val = raw_total.get('value')
                elif isinstance(raw_total, (int, str)): total_hits_val = raw_total
                if total_hits_val is not None:
                    try: total_hits = int(total_hits_val); print(f"Total potential hits: {total_hits}")
                    except (ValueError, TypeError): total_hits = None; print(f"Warn: Bad total hits '{total_hits_val}'")
                else: total_hits = None; print("Warn: Total hits not found.")

            # Stop conditions
            if total_hits == 0: break
            if total_hits is not None and len(all_vulnerabilities) >= total_hits: break
            if num_returned < page_size: break
            current_page += 1

        except requests.exceptions.Timeout:
            error_msg = f"API request timed out on page {current_page + 1}."
            print(f"Error: {error_msg}")
            raise HTTPException(status_code=504, detail=error_msg) # 504 Gateway Timeout
        except requests.exceptions.HTTPError as e:
            error_detail = f"{e.response.status_code}: "
            try: error_detail += e.response.text[:200]
            except Exception: error_detail += "(Could not read body)"
            print(f"Error: HTTP Error on page {current_page + 1}: {error_detail}")
            # Use detail from upstream if available, else generic message
            upstream_detail = f"Upstream API Error: {error_detail}"
            raise HTTPException(status_code=e.response.status_code, detail=upstream_detail)
        except Exception as e:
            print(f"Error: Unexpected error during pagination: {traceback.format_exc()}")
            raise HTTPException(status_code=500, detail=f"Unexpected pagination error: {e}")

    if current_page >= max_pages: print(f"Warning: Max pages ({max_pages}) reached.")
    print(f"Finished fetch. Total vulnerabilities retrieved: {len(all_vulnerabilities)}")
    return all_vulnerabilities

# --- FastAPI Endpoint ---
# Vercel maps requests to the root of this deployment to the FastAPI app.
# FastAPI then maps "/" to this function.
@app.get("/")
async def generate_stix_bundle_endpoint():
    """
    Generates STIX bundle based on fixed criteria and returns it.
    Handles GET requests to the root path.
    """
    print(f"[{datetime.now(timezone.utc).isoformat()}] FastAPI: Received request to generate STIX bundle...")

    # Define fixed API parameters for the Flashpoint query
    params = {
        "published_after": "-14d",
        "exploit": "public",
        "solution": "change_default,patch,upgrade,workaround",
        "location": "remote"
    }
    print(f"Using fixed filter parameters: {params}")

    try:
        # Fetch Data (synchronous helper in async route is okay for FastAPI)
        vulnerabilities = get_all_flashpoint_vulnerabilities(params)

        # Handle No Results
        if not vulnerabilities:
            print("No vulnerabilities found matching criteria.")
            empty_bundle = {
                "type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1",
                "objects": [TLP_WHITE_DEFINITION_DICT] # Use the dict version
            }
            return JSONResponse(content=empty_bundle)

        print(f"Found {len(vulnerabilities)}. Converting to STIX...")

        # Map to STIX
        all_stix_object_data = [] # Store serialized data (dicts)
        conversion_errors = 0
        for vuln_data in vulnerabilities:
             # map_flashpoint_vuln_to_stix returns list of stix2 objects
             stix2_objects = map_flashpoint_vuln_to_stix(vuln_data)
             if stix2_objects:
                 # Serialize each stix2 object to a dictionary
                 for stix2_obj in stix2_objects:
                     try:
                         all_stix_object_data.append(stix2_obj.serialize())
                     except Exception as serialize_err:
                         print(f"Error serializing STIX object {getattr(stix2_obj, 'id', 'N/A')}: {serialize_err}")
                         conversion_errors += 1 # Count serialization errors
             # Decide if empty list from mapper counts as error - let's assume not.

        print(f"STIX conversion done. Generated {len(all_stix_object_data)} objects. Encountered {conversion_errors} errors during mapping/serialization.")

        if not all_stix_object_data and vulnerabilities:
             err_msg = f"Mapping resulted in zero STIX objects (check mapping logic or serialization)."
             print(f"Warning: {err_msg}")
             # Return 200 but indicate potential issue in response
             empty_bundle = {
                 "type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1",
                 "objects": [TLP_WHITE_DEFINITION_DICT]
             }
             return JSONResponse(content=empty_bundle)

        # Construct Final Bundle (as a dictionary)
        final_bundle = {
          "type": "bundle",
          "id": f"bundle--{uuid.uuid4()}",
          "spec_version": "2.1",
          # Combine the TLP definition dict with the list of STIX object dicts
          "objects": [TLP_WHITE_DEFINITION_DICT] + all_stix_object_data
        }

        print(f"Successfully generated bundle with {len(all_stix_object_data)} primary objects.")
        # Use JSONResponse for explicit control over JSON serialization if needed,
        # but returning a dict usually works fine with FastAPI.
        return JSONResponse(content=final_bundle)

    except HTTPException as http_exc:
        # Re-raise HTTPExceptions (e.g., from API helper)
        # FastAPI will handle converting these to proper HTTP error responses
        raise http_exc
    except Exception as e:
        # Catch any other unexpected errors during the process
        print(f"Error during STIX bundle generation endpoint: {traceback.format_exc()}")
        # Return a standard 500 error
        raise HTTPException(status_code=500, detail=f"Internal server error during STIX generation: {e}")

# Optional: Add root endpoint for basic health check separate from STIX logic
@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    print(f"[{datetime.now(timezone.utc).isoformat()}] Health check invoked.")
    return {"status": "ok"}

# Note: Vercel runs the ASGI app `app` directly using an ASGI server like Uvicorn.
# This block is only for running locally (e.g., `python api/index.py`)
if __name__ == "__main__":
    import uvicorn
    print("Starting Uvicorn server for local development...")
    # Port 8000 is common for FastAPI local dev
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)