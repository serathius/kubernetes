#!/bin/bash

# A script to parse K8s apiserver logs and count the top 10 requests by
# userAgent, resource, subresource (if present), and verb.

# --- Configuration ---
# The namespace where the apiserver pods are running.
NAMESPACE="kube-system"
# The time window in seconds for collecting logs.
INTERVAL=10

# --- Script Logic ---
echo "🔍 Finding the kube-apiserver pod..."

APISERVER_POD=$(kubectl get pods -n "$NAMESPACE" -l component=kube-apiserver --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')

if [ -z "$APISERVER_POD" ]; then
    echo "❌ Error: Could not find any running kube-apiserver pod in namespace '$NAMESPACE'."
    exit 1
fi

echo "✅ Found apiserver pod: $APISERVER_POD"
echo "📊 Starting to monitor logs. New counts will be displayed every $INTERVAL seconds."
echo "   Press Ctrl+C to stop."
sleep 2

# --- Main Loop ---
while true; do
    clear
    echo "📈 Top 10 request counts by userAgent, resource, subresource, & verb in the last $INTERVAL seconds (at $(date +%T)):"
    echo "------------------------------------------------------------------"

    log_data=$(kubectl logs "$APISERVER_POD" -n "$NAMESPACE" --since=${INTERVAL}s 2>/dev/null)

    if [ -z "$log_data" ]; then
        echo "No new API server requests found in the last $INTERVAL seconds."
    else
        echo "$log_data" | \
            # Use awk for efficient, multi-field parsing.
            awk '
            {
                match($0, /userAgent="([^/"]+)/, ua_match)
                match($0, /URI="([^"]+)"/, uri_match)
                match($0, /verb="([^"]+)"/, verb_match)

                if (ua_match[1] && uri_match[1] && verb_match[1]) {
                    path = uri_match[1]
                    verb = verb_match[1]
                    
                    sub(/\?.*/, "", path)
                    sub(/^\/api\/v[0-9]+\//, "", path)
                    sub(/^\/apis\/[^\/]+\/v[^\/]+\//, "", path)
                    sub(/^namespaces\/[^\/]+\//, "", path)
                    
                    split(path, path_parts, "/")
                    resource = path_parts[1]
                    # ⭐ NEW: The subresource is the 3rd part of the path, after the resource name.
                    # If it does not exist, awk assigns an empty string, which is perfect.
                    subresource = path_parts[3]
                    
                    if (resource == "watch") {
                        resource = path_parts[2]
                    }
                    
                    # Print a combined key, now with the subresource.
                    if (resource != "") {
                        print ua_match[1] "," resource "," subresource "," verb
                    }
                }
            }' | \
            sort | \
            uniq -c | \
            sort -nr | \
            head -n 10 | \
            # Read each line and format it into Prometheus-style output.
            while read -r count combo; do
                # Efficiently split the "agent,resource,subresource,verb" string.
                IFS=',' read -r agent resource subresource verb <<< "$combo"
                
                # ⭐ NEW: Dynamically build the labels string.
                # This ensures the subresource label only appears when it has a value.
                labels="agent=\"$agent\", resource=\"$resource\""
                if [ -n "$subresource" ]; then
                    labels="$labels, subresource=\"$subresource\""
                fi
                labels="$labels, verb=\"$verb\""

                printf "apiserver_requests_total{%s} %s\n" "$labels" "$count"
            done
    fi

    sleep "$INTERVAL"
done
