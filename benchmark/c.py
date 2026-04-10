import requests
import re
import time
import os
import sys
from datetime import datetime

# --- Configuration ---
# The URL of your metrics endpoint
METRICS_URL = "https://192.168.8.2:10257/metrics"

# --- NEW: Specific metric names to monitor ---
# The full name of the GAUGE metric (latest sample)
GAUGE_METRIC_NAME = "michaelasp_current_watch_delay_seconds"

# The base name of the HISTOGRAM (e.g., "metric_name" which has _bucket, _count)
HISTOGRAM_METRIC_NAME = "michaelasp_watch_delay_seconds"

# How often to refresh the data, in seconds
REFRESH_INTERVAL = 2

# Which percentiles you want to calculate for the histogram
PERCENTILES_TO_CALCULATE = [50, 90, 95, 99, 99.9]

# --- End of Configuration ---


# Suppress the InsecureRequestWarning from using verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_metrics(text_data, gauge_name, histogram_name):
    """
    Parses both the gauge and histogram metrics from the raw text data.
    """
    latest_sample = None
    buckets = []
    total_count = None
    
    # --- UPDATED Regex ---
    # Matches the gauge, with or without labels
    gauge_regex = re.compile(
        rf'^{gauge_name}(?:\s*{{[^}}]*}})?\s+([\d\.]+)'
    )
    # Matches buckets, finding 'le' anywhere inside labels
    bucket_regex = re.compile(
        rf'^{histogram_name}_bucket\s*{{[^}}]*le="([^"]+)"[^}}]*}}\s+([\d\.]+)'
    )
    # Matches the count, with or without labels
    count_regex = re.compile(
        rf'^{histogram_name}_count(?:\s*{{[^}}]*}})?\s+([\d\.]+)'
    )

    for line in text_data.strip().split('\n'):
        if line.startswith('#'):
            continue
        
        gauge_match = gauge_regex.match(line)
        if gauge_match:
            latest_sample = float(gauge_match.group(1))
            continue
            
        bucket_match = bucket_regex.match(line)
        if bucket_match:
            le_str, count_str = bucket_match.groups()
            upper_bound = float('inf') if le_str == '+Inf' else float(le_str)
            count = int(float(count_str))
            buckets.append((upper_bound, count))
            continue
        
        count_match = count_regex.match(line)
        if count_match:
            total_count = int(float(count_match.group(1)))
            continue

    buckets.sort(key=lambda x: x[0])
    
    return {
        'latest_sample': latest_sample,
        'buckets': buckets,
        'total_count': total_count
    }


def calculate_percentiles(percentiles, buckets, total_count):
    """
    Calculates latency values for given percentiles using linear interpolation.
    """
    if not total_count or total_count == 0:
        return {p: 0 for p in percentiles}

    results = {}
    for p in percentiles:
        rank = (p / 100.0) * total_count
        prev_bound, prev_count = 0, 0
        found = False
        for upper_bound, count in buckets:
            if count >= rank:
                count_in_bucket = count - prev_count
                if count_in_bucket <= 0:
                    results[p] = prev_bound
                else:
                    # How far into this bucket's population is our rank?
                    rank_in_bucket = rank - prev_count
                    # What is the value-range of this bucket?
                    bucket_width = upper_bound - prev_bound
                    
                    # --- CORRECTED Interpolation Logic ---
                    estimated_value = prev_bound + (rank_in_bucket / count_in_bucket) * bucket_width
                    
                    results[p] = estimated_value
                found = True
                break
            prev_bound, prev_count = upper_bound, count
        if not found:
            results[p] = prev_bound # Fallback to the last finite bucket
            
    return results


def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    """Main loop to fetch, process, and display metrics."""
    print("🚀 Starting live latency monitor... (Press Ctrl+C to exit)")
    time.sleep(1)

    try:
        while True:
            try:
                # Fetch data from the URL, ignoring SSL verification (-k equivalent)
                response = requests.get(METRICS_URL, verify=False, timeout=15)
                response.raise_for_status() # Raise an exception for bad status codes

                # Parse the data
                metrics = parse_metrics(
                    response.text, 
                    GAUGE_METRIC_NAME, 
                    HISTOGRAM_METRIC_NAME
                )
                
                # Calculate percentiles
                percentiles = {}
                if metrics['buckets'] and metrics['total_count'] is not None:
                    percentiles = calculate_percentiles(
                        PERCENTILES_TO_CALCULATE, 
                        metrics['buckets'], 
                        metrics['total_count']
                    )

                # Display the results
                clear_screen()
                print(f"📈 Live Latency Monitor")
                print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("-" * 40)
                
                # Display latest sample
                if metrics['latest_sample'] is not None:
                    print(f"➡️  Latest Sample ({GAUGE_METRIC_NAME}):")
                    print(f"   {metrics['latest_sample']:.4f} s")
                else:
                    print(f"➡️  Latest Sample ({GAUGE_METRIC_NAME}): Not found")
                
                print(f"\n📊 Aggregated Percentiles ({HISTOGRAM_METRIC_NAME})")
                if percentiles:
                    for p, value in percentiles.items():
                        print(f"   p{p:<5}: {value:.4f} s")
                    print(f"\n   (Based on {metrics['total_count']} total observations)")
                else:
                    print("   Histogram data not found.")
                
                print("-" * 40)

            except requests.exceptions.RequestException as e:
                clear_screen()
                print(f"🚨 Network Error: Could not fetch metrics from {METRICS_URL}")
                print(f"   Error: {e}")
                print(f"   Retrying in {REFRESH_INTERVAL} seconds...")
            except Exception as e:
                clear_screen()
                print(f"An unexpected error occurred: {e}")

            time.sleep(REFRESH_INTERVAL)

    except KeyboardInterrupt:
        print("\n�� Monitor stopped. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
