#!/bin/bash

PARALLEL_JOBS=100
MIN=$1
MAX=$2

apply_statefulset() {
  local i=$1
  kubectl apply -f - <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-$i
  labels:
    app: nginx
spec:
  replicas: 64
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
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
EOF
}

export -f apply_statefulset
seq $MIN $MAX | xargs -I {} -P $PARALLEL_JOBS bash -c 'apply_statefulset "$@"' _ {}
