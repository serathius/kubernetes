#!/bin/bash

PARALLEL_JOBS=1000
MIN=$1
MAX=$2

apply_statefulset() {
  local i=$1
  kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: nginx-$i
spec:
  podManagementPolicy: "Parallel"
  replicas: 4
  selector:
    matchLabels:
      app: nginx-$i
  template:
    metadata:
      labels:
        app: nginx-$i
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: type
                operator: In
                values:
                - kwok
      tolerations:
      - key: "kwok.x-k8s.io/node"
        operator: "Exists"
        effect: "NoSchedule"
      containers:
      - name: nginx
        image: registry.k8s.io/nginx-slim:0.21
EOF
}

export -f apply_statefulset
seq $MIN $MAX | xargs -I {} -P $PARALLEL_JOBS bash -c 'apply_statefulset "$@"' _ {}
