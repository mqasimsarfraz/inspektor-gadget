---
title: KubeIPResolver
---

The KubeIPResolver operator enriches IP addresses with pod and service
information. For instance, in this example the `10.96.0.10` IP is enriched with
namespace, service name and labels:

```json
  "dst": {
    "addr": "10.96.0.10",
    "k8s": {
        "kind": "svc",
        "labels": "k8s-app=kube-dns,kubernetes.io/cluster-service=true,kubernetes.io/name=CoreDNS",
        "name": "kube-dns",
        "namespace": "kube-system"
    }
    "port": 53,
    "proto": 17,
    "version": 4
  }
```

## Parameters

None
