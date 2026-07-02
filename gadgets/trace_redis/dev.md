# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

The `sock_ops` and `fexit/tcp_connect` programs (`gadget_tcp_stream_sockops`, `gadget_tcp_stream_connect`) are **owned and attached by the framework** (`pkg/sockhash`, the `Sockhash` operator), not compiled into this gadget: they populate the connection tables and add sockets to the sockhash. The gadget only declares the shared maps via `<gadget/tcp_stream.h>` (the framework injects its instances through `MapReplacements`) and adds two programs of its own: `ig_redis_command` (`sk_msg`, send path) and `ig_redis_reply` (`sk_skb/stream_verdict`, receive path). The diagrams below include the framework programs (dashed) to show the full data flow.

### Flowchart

```mermaid
flowchart LR
events[("events")]
gadget_sockhash[("gadget_sockhash")]
gadget_tcp_stream_conns[("gadget_tcp_stream_conns")]
gadget_tcp_stream_tuples[("gadget_tcp_stream_tuples")]
redis_inflight[("redis_inflight")]
gadget_mntns_filter_map[("gadget_mntns_filter_map")]

gadget_tcp_stream_sockops -- "Lookup+Update" --> gadget_tcp_stream_conns
gadget_tcp_stream_sockops -- "Update" --> gadget_tcp_stream_tuples
gadget_tcp_stream_sockops -- "Update" --> gadget_sockhash
gadget_tcp_stream_sockops["gadget_tcp_stream_sockops"]

gadget_tcp_stream_connect -- "Lookup" --> gadget_tcp_stream_conns
gadget_tcp_stream_connect -- "Update" --> gadget_tcp_stream_tuples
gadget_tcp_stream_connect["gadget_tcp_stream_connect"]

ig_redis_command -- "Lookup" --> gadget_tcp_stream_tuples
ig_redis_command -- "Lookup" --> gadget_mntns_filter_map
ig_redis_command -- "Update" --> redis_inflight
ig_redis_command -- "EventOutput" --> events
ig_redis_command["ig_redis_command"]

ig_redis_reply -- "Lookup" --> gadget_tcp_stream_conns
ig_redis_reply -- "Lookup" --> gadget_mntns_filter_map
ig_redis_reply -- "Lookup+Delete" --> redis_inflight
ig_redis_reply -- "EventOutput" --> events
ig_redis_reply["ig_redis_reply"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant gadget_tcp_stream_sockops
participant gadget_tcp_stream_connect
participant ig_redis_command
participant ig_redis_reply
end
box eBPF Maps
participant gadget_tcp_stream_conns
participant gadget_tcp_stream_tuples
participant gadget_sockhash
participant redis_inflight
participant events
end
gadget_tcp_stream_sockops->>gadget_tcp_stream_conns: Update
gadget_tcp_stream_sockops->>gadget_tcp_stream_tuples: Update
gadget_tcp_stream_sockops->>gadget_sockhash: Update
gadget_tcp_stream_connect->>gadget_tcp_stream_conns: Lookup
gadget_tcp_stream_connect->>gadget_tcp_stream_tuples: Update
ig_redis_command->>gadget_tcp_stream_tuples: Lookup
ig_redis_command->>redis_inflight: Update
ig_redis_command->>events: EventOutput
ig_redis_reply->>gadget_tcp_stream_conns: Lookup
ig_redis_reply->>redis_inflight: Lookup
ig_redis_reply->>redis_inflight: Delete
ig_redis_reply->>events: EventOutput
```
