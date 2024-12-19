import argparse
import requests  # type: ignore
import json
import re

def load_waf_signatures(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def detect_waf(url, waf_signatures):
    try:
        response = requests.get(url, timeout=10)
        response_headers = response.headers
        response_text = response.text
        response_code = response.status_code

        print(f"Server response: {response_code}")

        detected_wafs = []
        for waf_name, signature in waf_signatures.items():
            code = signature.get("code", "")
            page = signature.get("page", "")
            headers = signature.get("headers", "")

            # Check response code
            if code and str(response_code) in code.split("|"):
                detected_wafs.append(waf_name)
                continue

            # Check page content
            if page:
                if re.search(page, response_text, re.IGNORECASE):
                    detected_wafs.append(waf_name)
                    continue

            # Check headers
            if headers:
                if re.search(headers, str(response_headers), re.IGNORECASE):
                    detected_wafs.append(waf_name)
                    continue

        if detected_wafs:
            print("Detected WAFs:")
            for waf in detected_wafs:
                print(f"- {waf}")
        else:
            print("No WAF detected.")

    except requests.exceptions.RequestException as e:
        print(f"Error during the request: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple WAF detector"
    )
    parser.add_argument(
        "url", type=str, help="Target URL to scan (e.g., https://example.com)"
    )
    parser.add_argument(
        "--signatures", type=str, default="waf_signatures.json",
        help="Path to the JSON file containing WAF signatures (default: waf_signatures.json)"
    )
    args = parser.parse_args()

    waf_signatures = load_waf_signatures(args.signatures)

    detect_waf(args.url, waf_signatures)