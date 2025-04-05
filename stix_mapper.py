# stix_mapper.py (Corrected and Complete: Fixes syntax, imports, markings, adds simplified Software/Relationship)

import json
from datetime import datetime, timezone
from stix2 import (Vulnerability, Software, Relationship, ExternalReference, Note, Bundle,
                   TLP_WHITE, StatementMarking, MarkingDefinition)
from stix2.utils import format_datetime # Only format_datetime needed from utils

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
    if not dt_string:
        return None
    try:
        needs_tz = 'Z' not in dt_string and '+' not in dt_string
        if needs_tz:
             parts = dt_string.split('T')
             if len(parts) == 1: dt_string += "T00:00:00Z"
             elif len(parts) == 2 and '-' not in parts[1].split(':')[-1]: dt_string += "Z"
        if dt_string.endswith('Z'): dt_string = dt_string[:-1] + '+00:00'
        dt_obj = datetime.fromisoformat(dt_string)
        if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
             print(f"Warning: Parsed datetime '{dt_string}' naive. Assuming UTC.")
             return dt_obj.replace(tzinfo=timezone.utc)
        return dt_obj
    except Exception as e:
        print(f"Warning: Could not parse datetime '{dt_string}': {e}")
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
    """
    if not fp_vuln_data or not fp_vuln_data.get('id'):
         print("Warning: Insufficient data provided to map vulnerability (missing ID). Skipping.")
         return []

    stix_objects = []
    software_cache = {} # Cache based on Vendor::Product name
    fp_id = fp_vuln_data.get('id')
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
    cve_ids_list = fp_vuln_data.get('cve_ids', [])
    if isinstance(cve_ids_list, list):
        for cve_id in cve_ids_list:
             if cve_id and isinstance(cve_id, str): external_references.append(ExternalReference(source_name="cve", external_id=cve_id))
    cwes_list = fp_vuln_data.get('cwes', [])
    if isinstance(cwes_list, list):
        for cwe_info in cwes_list:
             if isinstance(cwe_info, dict):
                 cwe_id_val = cwe_info.get('cwe_id')
                 if cwe_id_val:
                      try: external_references.append(ExternalReference(source_name="cwe", external_id=f"CWE-{int(cwe_id_val)}"))
                      except (ValueError, TypeError): print(f"Warning: Invalid CWE ID format '{cwe_id_val}' for vuln {fp_id}")
    ext_refs_list = fp_vuln_data.get('ext_references', [])
    if isinstance(ext_refs_list, list):
        for ref in ext_refs_list:
             if not isinstance(ref, dict): continue
             ref_type = ref.get('type'); ref_value = ref.get('value')
             if not (ref_type and ref_value and isinstance(ref_value, str)): continue
             source_name = map_ext_ref_type(ref_type)
             if source_name:
                 id_val = f"CWE-{ref_value}" if source_name == 'cwe' else ref_value
                 is_duplicate = any(er.source_name == source_name and er.external_id == id_val for er in external_references)
                 if not is_duplicate: external_references.append(ExternalReference(source_name=source_name, external_id=ref_value))
             elif 'url' in ref_type.lower(): external_references.append(ExternalReference(source_name=ref_type, url=ref_value))
    external_references.append(ExternalReference(source_name="Flashpoint Vulnerability Intelligence", description=f"Flashpoint Vulnerability ID: {fp_id}"))

    # --- Labels ---
    labels = []
    tags_list = fp_vuln_data.get('tags', [])
    if isinstance(tags_list, list):
        for tag in tags_list:
             if tag and isinstance(tag, str): labels.append(f"fp-tag:{tag}")
    scores_dict = fp_vuln_data.get('scores', {})
    if not isinstance(scores_dict, dict): scores_dict = {}
    severity = scores_dict.get('severity')
    if severity and isinstance(severity, str): labels.append(f"fp-severity:{severity.lower()}")
    status = fp_vuln_data.get('vuln_status')
    if status and isinstance(status, str): labels.append(f"fp-status:{status.lower()}")
    classifications_list = fp_vuln_data.get('classifications', [])
    if isinstance(classifications_list, list):
        for classification in classifications_list:
             if isinstance(classification, dict):
                 class_name = classification.get('name')
                 if class_name and isinstance(class_name, str): labels.append(f"fp-classification:{class_name}")
    if exploit_published_at: labels.append("exploit-available")

    # --- Description Enhancements ---
    full_description = fp_description
    if fp_solution: full_description += f"\n\nSolution: {fp_solution}"
    if fp_creditees and isinstance(fp_creditees, list):
        creds = ", ".join([c.get('name', 'Unknown') for c in fp_creditees if isinstance(c, dict) and c.get('name')])
        if creds: full_description += f"\n\nCredits: {creds}"
    if isinstance(disclosed_at, datetime): full_description += f"\n\nDisclosed On: {format_datetime(disclosed_at)}"
    if isinstance(exploit_published_at, datetime): full_description += f"\n\nExploit Published On: {format_datetime(exploit_published_at)}"

    # --- CVSS Scores and Extensions (Dictionary Method) ---
    extensions = {}
    cvss_v3_list = fp_vuln_data.get('cvss_v3s', [])
    if cvss_v3_list and isinstance(cvss_v3_list, list) and cvss_v3_list:
        cvss_v3_data = cvss_v3_list[0]
        if isinstance(cvss_v3_data, dict):
            # --- CORRECTED Syntax for score parsing ---
            base_score_v3, temporal_score_v3 = None, None
            try: # Parse scores safely
                if cvss_v3_data.get('score') is not None:
                    base_score_v3 = float(cvss_v3_data['score'])
                if cvss_v3_data.get('temporal_score') is not None:
                    temporal_score_v3 = float(cvss_v3_data['temporal_score'])
            except (ValueError, TypeError):
                print(f"Warning: Could not parse CVSSv3 score for vuln {fp_id}")
                base_score_v3, temporal_score_v3 = None, None
            # --- End Correction ---
            cvss_v3_dict = { "spec_version": "3.1", "version": str(cvss_v3_data.get('version', '3.1')), "vectorString": cvss_v3_data.get('vector_string'), "baseScore": base_score_v3, "attackVector": cvss_v3_data.get('attack_vector'), "attackComplexity": cvss_v3_data.get('attack_complexity'), "privilegesRequired": cvss_v3_data.get('privileges_required'), "userInteraction": cvss_v3_data.get('user_interaction'), "scope": cvss_v3_data.get('scope'), "confidentialityImpact": cvss_v3_data.get('confidentiality_impact'), "integrityImpact": cvss_v3_data.get('integrity_impact'), "availabilityImpact": cvss_v3_data.get('availability_impact'), "exploitCodeMaturity": cvss_v3_data.get('exploit_code_maturity'), "remediationLevel": cvss_v3_data.get('remediation_level'), "reportConfidence": cvss_v3_data.get('report_confidence'), "temporalScore": temporal_score_v3, "baseSeverity": severity if severity else None }
            cvss_v3_dict_filtered = {k: v for k, v in cvss_v3_dict.items() if v is not None}
            if cvss_v3_dict_filtered: extensions[CVSSV3_EXTENSION_ID] = cvss_v3_dict_filtered

    cvss_v2_list = fp_vuln_data.get('cvss_v2s', [])
    if cvss_v2_list and isinstance(cvss_v2_list, list) and cvss_v2_list:
        cvss_v2_data = cvss_v2_list[0]
        if isinstance(cvss_v2_data, dict):
            # --- CORRECTED Syntax for score parsing ---
            base_score_v2 = None
            try:
                if cvss_v2_data.get('score') is not None:
                    base_score_v2 = float(cvss_v2_data['score'])
            except (ValueError, TypeError):
                print(f"Warning: Could not parse CVSSv2 score for vuln {fp_id}")
                base_score_v2 = None
            # --- End Correction ---
            cvss_v2_dict = { "spec_version": "2.0", "version": "2.0", "baseScore": base_score_v2, "accessVector": cvss_v2_data.get('access_vector'), "accessComplexity": cvss_v2_data.get('access_complexity'), "authentication": cvss_v2_data.get('authentication'), "confidentialityImpact": cvss_v2_data.get('confidentiality_impact'), "integrityImpact": cvss_v2_data.get('integrity_impact'), "availabilityImpact": cvss_v2_data.get('availability_impact'), }
            cvss_v2_dict_filtered = {k: v for k, v in cvss_v2_dict.items() if v is not None}
            if cvss_v2_dict_filtered: extensions[CVSSV2_EXTENSION_ID] = cvss_v2_dict_filtered

    # --- Custom Properties ---
    custom_props = {}
    cvss_v4_list = fp_vuln_data.get('cvss_v4s', [])
    if cvss_v4_list and isinstance(cvss_v4_list, list) and cvss_v4_list:
        cvss_v4_data = cvss_v4_list[0]
        if isinstance(cvss_v4_data, dict):
            # --- CORRECTED Syntax for score parsing ---
            base_score_v4, threat_score_v4 = None, None
            try:
                if cvss_v4_data.get('score') is not None: base_score_v4 = float(cvss_v4_data['score'])
                if cvss_v4_data.get('threat_score') is not None: threat_score_v4 = float(cvss_v4_data['threat_score'])
            except (ValueError, TypeError):
                print(f"Warning: Could not parse CVSSv4 score for vuln {fp_id}")
                base_score_v4, threat_score_v4 = None, None
            # --- End Correction ---
            cvss_v4_prop_dict = {k: v for k, v in cvss_v4_data.items() if v is not None}
            if base_score_v4 is not None: cvss_v4_prop_dict['baseScore'] = base_score_v4
            elif 'score' in cvss_v4_prop_dict: del cvss_v4_prop_dict['score']
            if threat_score_v4 is not None: cvss_v4_prop_dict['threatScore'] = threat_score_v4
            elif 'threat_score' in cvss_v4_prop_dict: del cvss_v4_prop_dict['threat_score']
            if cvss_v4_prop_dict: custom_props['x_flashpoint_cvssv4'] = cvss_v4_prop_dict
    epss_score = scores_dict.get('epss_score')
    if epss_score is not None:
        try: custom_props['x_flashpoint_epss_score'] = float(epss_score)
        except (ValueError, TypeError): print(f"Warning: Could not parse EPSS score '{epss_score}' for vuln {fp_id}")

    # --- Create Vulnerability Object ---
    try:
        vulnerability = Vulnerability(
            name=fp_title or f"Flashpoint Vulnerability {fp_id}",
            description=full_description,
            created=created_at,
            modified=modified_at,
            external_references=external_references,
            labels=sorted(list(set(labels))),
            extensions=extensions if extensions else None,
            object_marking_refs=[TLP_WHITE_DEFINITION.id], # Use ID
            allow_custom=True,
            **custom_props
        )
        stix_objects.append(vulnerability)
    except Exception as e:
        print(f"ERROR: Failed to create Vulnerability SDO for ID {fp_id}: {e}")
        return [] # Skip this vulnerability if core object fails

    # --- Process Affected Products (Vendor/Product Only - Updated Logic) ---
    products_list = fp_vuln_data.get('products', [])
    vendors_list = fp_vuln_data.get('vendors', []) # Get top-level vendors list

    # Create a lookup map for vendor IDs to names for efficiency
    vendor_map = {}
    if isinstance(vendors_list, list):
        vendor_map = {v.get('id'): v.get('name') for v in vendors_list if isinstance(v, dict) and v.get('id') and v.get('name')}

    if isinstance(products_list, list):
        for i, product_info in enumerate(products_list):
            if not isinstance(product_info, dict): continue
            product_name = product_info.get('name')
            if not product_name: continue # Skip if no product name

            vendor_name = None
            # Attempt 1: Get vendor name directly from product object
            vendor_name = product_info.get('vendor')
            # Attempt 2: If not found, try lookup using vendor_id from product object
            if not vendor_name:
                vendor_id = product_info.get('vendor_id')
                if vendor_id and vendor_id in vendor_map:
                    vendor_name = vendor_map.get(vendor_id)
            # Attempt 3: If still not found, assume positional correspondence if only 1 product/vendor
            if not vendor_name and len(products_list) == 1 and len(vendors_list) == 1:
                 if isinstance(vendors_list[0], dict):
                      vendor_name = vendors_list[0].get('name')
                      print(f"Info: Assuming single vendor '{vendor_name}' matches single product '{product_name}' for vuln {fp_id}")

            # If we still couldn't determine a vendor name, skip
            if not vendor_name:
                 print(f"Warning: Could not determine vendor for product '{product_name}' (vuln {fp_id}). Skipping software/relationship creation.")
                 continue

            # Create Software object (NO VERSION)
            cache_key = f"{vendor_name}::{product_name}" # Cache key

            try: # Wrap software/relationship creation
                if cache_key not in software_cache:
                    software = Software( name=product_name, vendor=vendor_name,
                        object_marking_refs=[TLP_WHITE_DEFINITION.id], allow_custom=True )
                    stix_objects.append(software)
                    software_cache[cache_key] = software
                    print(f"Info: Created Software object for {product_name} by {vendor_name}")
                else:
                    software = software_cache[cache_key]
                    print(f"Info: Reused cached Software object for {product_name} by {vendor_name}")

                # Create Relationship: Vulnerability -> has -> Software
                vuln_id_desc = next((ref.external_id for ref in external_references if ref.source_name == 'cve'), f"FP-{fp_id}")
                rel_desc = f"Vulnerability {vuln_id_desc} affects {product_name} (by {vendor_name})"
                rel = Relationship( vulnerability, 'has', software, description=rel_desc,
                                    object_marking_refs=[TLP_WHITE_DEFINITION.id] )
                stix_objects.append(rel)
            except Exception as e_sw_rel:
                print(f"ERROR: Failed creating base Software/Relationship for product '{product_name}' (vuln {fp_id}): {e_sw_rel}")

    return stix_objects