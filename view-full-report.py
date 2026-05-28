import sys
import json
import traceback
from model_security_client.api import ModelSecurityAPIClient
from violations import get_scan_violations
from evaluations import get_scan_evaluations
from get_html import generate_html_report
from hf_sbom import fetch_hf_metadata, create_manual_sbom

BASE_URL = "https://api.sase.paloaltonetworks.com/aims"

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 view-full-report.py <scan_id>")
        sys.exit(1)

    scan_id = sys.argv[1]

    try:
        client = ModelSecurityAPIClient(base_url=BASE_URL)

        print(f"\n📄 Fetching scan details for: {scan_id}\n")
        scan = client.get_scan(scan_id)
        
        target_url = scan.model_uri
        model_id = target_url.replace("https://huggingface.co/", "")

        print("✅ Scan Report")
        print(scan.model_dump_json(indent=2))
       
        print("\n🔍 Fetching evaluations...\n")
        evaluations = get_scan_evaluations(scan_id)

        print("\n🚨 Fetching violations...\n")
        violations = get_scan_violations(scan_id)
        
        # 1. Fetch metadata and build manual SBOM directly from HF API
        hf_data = fetch_hf_metadata(model_id)
        manual_sbom = create_manual_sbom(scan_id, hf_data)
        report_filename = f"{scan_id}_report.html"
        scan_safe_dict = json.loads(scan.model_dump_json())

        if not violations or not violations.get("violations"):
            print("🎉 No violations found")
            generate_html_report(scan_safe_dict, evaluations, violations, manual_sbom, report_filename)
        else:   
            items = violations["violations"]
            print(f"❌ Violations Found: {len(items)}\n")
            print(json.dumps(violations, indent=2))
            generate_html_report(scan_safe_dict, evaluations, violations, manual_sbom, report_filename)

    except Exception as e:
        print(f"❌ Failed: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()