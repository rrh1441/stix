# stix_mapper.py (Place in stix repo root)
# Full content as provided previously - ensure this exact code is used.
import json
from datetime import datetime, timezone
from stix2 import (Vulnerability, Software, Relationship, ExternalReference, Note, Bundle,
                   TLP_WHITE, StatementMarking, MarkingDefinition)
from stix2.utils import format_datetime
import traceback # Added for potential debugging

# --- Constants ---
CVSSV3_EXTENSION_ID = "extension-definition--66e2492a-bbd3-4be6-88f5-cc91a017ac34"
CVSSV2_EXTENSION_ID = "extension-definition--39fc358f-1069-482c-a033-80cd5676f1e6"
TLP_WHITE_DEFINITION = MarkingDefinition(
     id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", # Stable ID for TLP:WHITE
     definition_type="statement",
     definition={"statement": "TLP:WHITE"}
)

# --- Helper Functions ---
def parse_flashpoint_datetime(dt_string):
    """Safely parses Flashpoint datetime strings into timezone-aware datetimes using built-in methods."""
    if not dt_string: return None
    try:
        needs_tz = 'Z' not in dt_string and '+' not in dt_string
        if needs_tz:
            parts = dt_string.split('T')
            if len(parts) == 1: dt_string += "T00:00:00Z"
            elif len(parts) == 2 and '-' not in parts[1].split(':')[-1]: dt_string += "Z"
        if dt_string.endswith('Z'): dt_string = dt_string[:-1] + '+00:00'
        dt_obj = datetime.fromisoformat(dt_string)
        if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
            print(f"[stix_mapper] Warning: Parsed datetime '{dt_string}' naive. Assuming UTC.")
            # Return the naive object for stix2 library, it handles timezone conversion often
            return dt_obj.replace(tzinfo=timezone.utc) # Or return naive and let stix2 handle? Test this. Let's return UTC-aware.
        return dt_obj
    except Exception as e:
        print(f"[stix_mapper] Warning: Could not parse datetime '{dt_string}': {e}")
        return None

def map_ext_ref_type(fp_ref_type):
    """Maps Flashpoint reference type to STIX source_name or returns None."""
    if not fp_ref_type: return None
    fp_ref_type = fp_ref_type.lower()
    if fp_ref_type == 'cve id': return 'cve'
    elif fp_ref_type == 'cwe id': return 'cwe'
    elif 'url' in fp_ref_type: return None
    return None

# --- Main Mapping Function ---
def map_flashpoint_vuln_to_stix(fp_vuln_data):
    """
    Maps a single Flashpoint Vulnerability JSON object to a list of STIX 2.1 objects.
    Includes base Software/Relationship mapping. Compatible with stix2==3.0.1.
    Returns a list of stix2 library objects.
    """
    if not fp_vuln_data or not fp_vuln_data.get('id'):
        print("[stix_mapper] Warning: Insufficient data provided to map vulnerability (missing ID). Skipping.")
        return []

    stix_objects = []
    software_cache = {} # Cache based on Vendor::Product name
    fp_id = fp_vuln_data.get('id')

    try: # Wrap major parts in try/except for better error isolation
        fp_title = fp_vuln_data.get('title')
        fp_description = fp_vuln_data.get('description', '')
        fp_solution = fp_vuln_data.get('solution')
        fp_creditees = fp_vuln_data.get('creditees')

        # --- Timestamps ---
        timelines = fp_vuln_data.get('timelines', {})
        if not isinstance(timelines, dict): timelines = {}
        created_at = parse_flashpoint_datetime(timelines.get('published_at'))
        modified_at = parse_flashpoint_datetime(timelines.get('last_modified_at'))
        disclosed_at = parse_flashpoint_datetime(timelines.get('disclosed_at'))
        exploit_published_at = parse_flashpoint_datetime(timelines.get('exploit_published_at'))

        # --- External References ---
        external_references = []
        added_refs = set()
        # CVEs
        for cve_id in fp_vuln_data.get('cve_ids', []):
            if cve_id and isinstance(cve_id, str) and f"cve:{cve_id}" not in added_refs:
                external_references.append(ExternalReference(source_name="cve", external_id=cve_id))
                added_refs.add(f"cve:{cve_id}")
        # CWEs
        for cwe_info in fp_vuln_data.get('cwes', []):
            if isinstance(cwe_info, dict) and cwe_info.get('cwe_id'):
                 cwe_id_val = str(cwe_info['cwe_id']).replace('CWE-', '')
                 try:
                     cwe_ext_id = f"CWE-{int(cwe_id_val)}"
                     if f"cwe:{cwe_ext_id}" not in added_refs:
                         external_references.append(ExternalReference(source_name="cwe", external_id=cwe_ext_id))
                         added_refs.add(f"cwe:{cwe_ext_id}")
                 except (ValueError, TypeError): print(f"[stix_mapper] Warning: Invalid CWE ID format '{cwe_info['cwe_id']}' for vuln {fp_id}")
        # Other refs
        for ref in fp_vuln_data.get('ext_references', []):
             if isinstance(ref, dict) and ref.get('type') and ref.get('value'):
                 ref_type_str = str(ref['type'])
                 ref_value_str = str(ref['value'])
                 source_name = map_ext_ref_type(ref_type_str)
                 if source_name:
                     ref_key = f"{source_name}:{ref_value_str}"
                     if ref_key not in added_refs:
                         external_references.append(ExternalReference(source_name=source_name, external_id=ref_value_str))
                         added_refs.add(ref_key)
                 elif 'url' in ref_type_str.lower():
                     ref_key = f"url:{ref_value_str}"
                     if ref_key not in added_refs:
                         external_references.append(ExternalReference(source_name=ref_type_str, url=ref_value_str))
                         added_refs.add(ref_key)
        external_references.append(ExternalReference(source_name="Flashpoint", description=f"Flashpoint ID: {fp_id}")) # Shortened name

        # --- Labels ---
        labels = set()
        for tag in fp_vuln_data.get('tags', []):
            if tag and isinstance(tag, str): labels.add(f"fp-tag:{tag.strip().replace(' ', '-').lower()}")
        scores_dict = fp_vuln_data.get('scores', {})
        if isinstance(scores_dict, dict):
            severity = scores_dict.get('severity')
            if severity and isinstance(severity, str): labels.add(f"fp-severity:{severity.lower()}")
            epss_score_val = scores_dict.get('epss_score') # Keep separate for custom prop
        status = fp_vuln_data.get('vuln_status')
        if status and isinstance(status, str): labels.add(f"fp-status:{status.lower().replace(' ', '-')}")
        for classification in fp_vuln_data.get('classifications', []):
            if isinstance(classification, dict) and classification.get('name'):
                labels.add(f"fp-classification:{str(classification['name']).strip().replace(' ', '-').lower()}")
        if exploit_published_at: labels.add("exploit-available")
        sorted_labels = sorted(list(labels))

        # --- Description ---
        full_description = fp_description
        if fp_solution: full_description += f"\n\nSolution: {fp_solution}"
        if fp_creditees and isinstance(fp_creditees, list):
            creds = ", ".join([c.get('name', 'Unknown') for c in fp_creditees if isinstance(c, dict) and c.get('name')])
            if creds: full_description += f"\n\nCredits: {creds}"
        if disclosed_at: full_description += f"\n\nDisclosed On: {format_datetime(disclosed_at)}"
        if exploit_published_at: full_description += f"\n\nExploit Published On: {format_datetime(exploit_published_at)}"

        # --- CVSS Scores & Extensions ---
        extensions = {}
        cvss_v3_list = fp_vuln_data.get('cvss_v3s', [])
        if cvss_v3_list and isinstance(cvss_v3_list, list) and cvss_v3_list[0]:
            cvss_v3_data_in = cvss_v3_list[0]
            if isinstance(cvss_v3_data_in, dict):
                cvss_v3_dict = {k: v for k, v in cvss_v3_data_in.items() if v is not None} # Filter nulls
                try:
                    if 'score' in cvss_v3_dict: cvss_v3_dict['baseScore'] = float(cvss_v3_dict.pop('score'))
                    if 'temporal_score' in cvss_v3_dict: cvss_v3_dict['temporalScore'] = float(cvss_v3_dict.pop('temporal_score'))
                    if 'version' in cvss_v3_dict: cvss_v3_dict['version'] = str(cvss_v3_dict['version'])
                    # Add spec_version and potentially baseSeverity if available from scores
                    cvss_v3_dict['spec_version'] = cvss_v3_dict.get('version', '3.1').split('.')[0] + '.x' # Or just 3.1? Let's try 3.1
                    cvss_v3_dict['spec_version'] = "3.1"
                    if scores_dict.get('severity'): cvss_v3_dict['baseSeverity'] = scores_dict['severity']
                    if len(cvss_v3_dict) > 2: extensions[CVSSV3_EXTENSION_ID] = cvss_v3_dict
                except (ValueError, TypeError) as e: print(f"[stix_mapper] Warning: CVSSv3 score parse error for vuln {fp_id}: {e}")

        cvss_v2_list = fp_vuln_data.get('cvss_v2s', [])
        if cvss_v2_list and isinstance(cvss_v2_list, list) and cvss_v2_list[0]:
            cvss_v2_data_in = cvss_v2_list[0]
            if isinstance(cvss_v2_data_in, dict):
                 cvss_v2_dict = {k: v for k, v in cvss_v2_data_in.items() if v is not None}
                 try:
                     if 'score' in cvss_v2_dict: cvss_v2_dict['baseScore'] = float(cvss_v2_dict.pop('score'))
                     cvss_v2_dict['spec_version'] = "2.0"
                     cvss_v2_dict['version'] = "2.0"
                     if len(cvss_v2_dict) > 2: extensions[CVSSV2_EXTENSION_ID] = cvss_v2_dict
                 except (ValueError, TypeError) as e: print(f"[stix_mapper] Warning: CVSSv2 score parse error for vuln {fp_id}: {e}")

        # --- Custom Properties ---
        custom_props = {}
        # CVSS v4
        cvss_v4_list = fp_vuln_data.get('cvss_v4s', [])
        if cvss_v4_list and isinstance(cvss_v4_list, list) and cvss_v4_list[0]:
            if isinstance(cvss_v4_list[0], dict) and len(cvss_v4_list[0]) > 0:
                 custom_props['x_flashpoint_cvssv4'] = cvss_v4_list[0]
        # EPSS
        epss_score_val = scores_dict.get('epss_score')
        if epss_score_val is not None:
            try: custom_props['x_flashpoint_epss_score'] = float(epss_score_val)
            except (ValueError, TypeError): print(f"[stix_mapper] Warning: Could not parse EPSS score '{epss_score_val}' for vuln {fp_id}")

        # --- Create Vulnerability Object ---
        # Use datetime objects for created/modified if available, else None
        vulnerability = Vulnerability(
            name=fp_title or f"Flashpoint Vulnerability {fp_id}",
            description=full_description,
            created=created_at,
            modified=modified_at,
            external_references=external_references,
            labels=sorted_labels,
            extensions=extensions if extensions else None,
            object_marking_refs=[TLP_WHITE_DEFINITION], # Pass the object itself
            allow_custom=True,
            **custom_props
        )
        stix_objects.append(vulnerability)

        # --- Process Affected Products ---
        products_list = fp_vuln_data.get('products', [])
        vendors_list = fp_vuln_data.get('vendors', [])
        vendor_map = {v.get('id'): v.get('name') for v in vendors_list if isinstance(v, dict) and v.get('id') and v.get('name')} if vendors_list else {}

        if isinstance(products_list, list):
            for product_info in products_list:
                if not isinstance(product_info, dict) or not product_info.get('name'): continue
                product_name = product_info['name']
                vendor_name = product_info.get('vendor')
                if not vendor_name:
                    vendor_id = product_info.get('vendor_id')
                    if vendor_id and vendor_map.get(vendor_id): vendor_name = vendor_map[vendor_id]
                if not vendor_name and len(products_list) == 1 and len(vendors_list) == 1 and vendors_list[0].get('name'):
                     vendor_name = vendors_list[0]['name']
                if not vendor_name:
                    print(f"[stix_mapper] Warning: Could not determine vendor for product '{product_name}' (vuln {fp_id}).")
                    continue

                cache_key = f"{vendor_name}::{product_name}"
                if cache_key not in software_cache:
                    software = Software(
                        name=product_name,
                        vendor=vendor_name,
                        object_marking_refs=[TLP_WHITE_DEFINITION],
                        allow_custom=True
                    )
                    stix_objects.append(software)
                    software_cache[cache_key] = software
                else:
                    software = software_cache[cache_key]

                # Create Relationship
                vuln_id_desc = next((ref.external_id for ref in external_references if ref.source_name == 'cve'), f"FP-{fp_id}")
                rel_desc = f"Vulnerability {vuln_id_desc} affects {product_name} (by {vendor_name})"
                rel = Relationship(
                    vulnerability,
                    'affects', # Use 'affects' relationship type
                    software,
                    description=rel_desc,
                    object_marking_refs=[TLP_WHITE_DEFINITION],
                    allow_custom=True
                )
                stix_objects.append(rel)

    except Exception as e:
        print(f"ERROR processing vuln {fp_id} in stix_mapper: {e}")
        print(traceback.format_exc())
        return [] # Return empty list if major error occurs during mapping

    return stix_objects # Return list of stix2 library objects