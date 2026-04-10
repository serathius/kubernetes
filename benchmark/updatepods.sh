#!/bin/bash

THROUGHPUT=2000
STATEFULSET_COUNT=2000
POD_COUNT=64
KUBE_NAMESPACE="default"
ANNOTATION_KEY="updater.example.com/last-updated"
# Slashes in annotation keys must be escaped for the JSON patch path
ANNOTATION_KEY_ESCAPED=$(echo $ANNOTATION_KEY | sed 's/\//~1/g')

# 1. Start kubectl proxy in the background
echo "Starting kubectl proxy..."
kubectl proxy &
PROXY_PID=$!

# 2. Set up a trap to kill the proxy on script exit (CTRL+C, etc.)
trap 'echo "Stopping kubectl proxy..."; kill $PROXY_PID' EXIT

# Give the proxy a moment to start up
sleep 1
echo "Proxy started with PID: $PROXY_PID"
echo "---"

# 3. The function to update one random pod via curl
update_random_pod_raw() {
    local statefulset=$(((RANDOM % $STATEFULSET_COUNT) + 1))
    local pod=$(((RANDOM % $POD_COUNT)))
    local pod_name="nginx-${statefulset}-${pod}"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ.%N")

    # The API endpoint for the specific pod
    local api_path="http://127.0.0.1:8001/api/v1/namespaces/$KUBE_NAMESPACE/pods/$pod_name"

    # The JSON merge-patch payload
    local payload
    payload=$(printf '{"metadata":{"annotations":{"%s":"%s"}}}' "$ANNOTATION_KEY" "$timestamp")

    # Send the raw PATCH request, suppressing output
    curl -s -o /dev/null -X PATCH -H "Content-Type: application/merge-patch+json" --data "$payload" "$api_path"
}

export -f update_random_pod_raw

INTERVAL=$(echo "scale=4; 1 / $THROUGHPUT" | bc)

# --- Main Control Loop (Worker Pool Model) ---
while true; do
    job_count=$(jobs -p | wc -l)

    update_random_pod_raw &
    sleep $INTERVAL
done
