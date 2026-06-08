#!/usr/bin/env python3
import urllib.request
import json
import ssl
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Analyze TestGrid JSON to find flakes and build IDs.")
    parser.add_argument("--dashboard", required=True, help="Dashboard name (e.g., sig-etcd-main-periodics)")
    parser.add_argument("--tab", required=True, help="Tab name (e.g., ci-etcd-integration-1-cpu-amd64)")
    parser.add_argument("--test-name", help="Specific test name to find build IDs for failures")
    
    args = parser.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = f"https://testgrid.k8s.io/{args.dashboard}/table?&dashboard={args.dashboard}&tab={args.tab}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx) as response:
            data = json.loads(response.read().decode())
    except Exception as e:
        print(f"Error fetching TestGrid data: {e}", file=sys.stderr)
        sys.exit(1)

    columns = data.get('column_ids', [])
    
    print(f"--- Dashboard: {args.dashboard} | Tab: {args.tab} ---")
    
    for row in data.get('tests', []):
        test_name = row.get('name', 'Unknown')
        
        # If looking for a specific test, skip others
        if args.test_name and args.test_name not in test_name:
            continue
            
        statuses = row.get('statuses', [])
        fail_count = 0
        failed_build_ids = []
        
        idx = 0
        for status in statuses:
            val = status.get('value', 0)
            count = status.get('count', 0)
            for _ in range(count):
                # 4=FAIL, 12=FAIL, 13=FLAKY
                if val in (4, 12, 13):
                    fail_count += 1
                    if idx < len(columns):
                        # Prow build IDs are sometimes prefixed with \ue000, strip it
                        build_id = columns[idx].replace('\ue000', '')
                        failed_build_ids.append(build_id)
                idx += 1
                
        if fail_count > 0:
            print(f"Test: {test_name}")
            print(f"  Failures: {fail_count}")
            if args.test_name:
                print(f"  Failed Build IDs: {', '.join(failed_build_ids)}")

if __name__ == "__main__":
    main()
