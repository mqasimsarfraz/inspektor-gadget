/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * Consumer side of the plumbing for gadgets that observe TCP-stream application
 * protocols (DNS-over-TCP, HTTP, ...) using the sk_skb + sk_msg program types.
 *
 * For a full walkthrough see the developer guide:
 * https://www.inspektor-gadget.io/docs/latest/gadget-devel/tcp-stream-gadgets
 *
 * The producer side -- the sock_ops program that selects sockets and the
 * fexit/tcp_connect program that captures process info, together with the
 * SOCKHASH and connection maps they populate -- is owned and attached by the
 * framework (see pkg/sockhash and pkg/operators/sockhash), not compiled into the
 * gadget. This header only declares the maps (so the gadget's programs can
 * reference them; the framework replaces them with its own instances via
 * MapReplacements) and the read-side helpers the gadget uses.
 *
 * A gadget only needs to:
 *   1. #include <gadget/tcp_stream.h>
 *   2. Declare the ports it wants tracked via its sockhash operator params in
 *      gadget.yaml (the framework's sock_ops applies the filter).
 *   3. Write a SEC("sk_skb/stream_verdict") program that parses received data
 *      and returns SK_PASS. Use gadget_tcp_stream_lookup(skb) to get the
 *      connection (tuple + process enrichment).
 *   4. (optionally, but recommended) Write a SEC("sk_skb/stream_parser")
 *      program that returns the length of the next complete application
 *      message. When present, the kernel's stream parser (strparser) buffers
 *      and reassembles TCP segments so the verdict program is always invoked
 *      with one complete message, even when it spans multiple TCP segments
 *      (e.g. a large DNS response or an HTTP body). Without a parser, the
 *      verdict runs on whatever in-order bytes TCP just made available, which
 *      may be a partial message.
 *   5. (optionally) Write a SEC("sk_msg") program to also observe the data the
 *      client *sends* (the verdict only sees received data). Use
 *      gadget_tcp_stream_msg_lookup(msg) to get the connection. sk_msg reads
 *      its payload via bpf_msg_pull_data() + data/data_end rather than
 *      bpf_skb_load_bytes().
 *
 * Inspektor Gadget attaches the sk_skb/sk_msg programs automatically based on
 * their section names to the framework SOCKHASH (configurable via
 * "programs.<name>.attach_to").
 *
 * Container / Kubernetes enrichment:
 *   Each recorded connection carries a struct gadget_process (conn->proc),
 *   populated by the framework producer for the active (client) side with the
 *   process that called connect() -- including its mount namespace. Copying
 *   conn->proc into a gadget event (event->proc) lets Inspektor Gadget enrich
 *   the event with the owning container and Kubernetes pod metadata. This works
 *   even though the sk_skb/sk_msg programs run in a context where the current
 *   process is unknown, because the capture happens in the connect() syscall
 *   context and is correlated to the socket (by cookie on the receive path, by
 *   4-tuple on the send path). The passive (server) side has no connect() call,
 *   so its conn->proc is left zeroed.
 */

#ifndef __GADGET_TCP_STREAM_H
#define __GADGET_TCP_STREAM_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/types.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * Connection recorded by the framework sock_ops program, keyed by the (stable)
 * socket cookie. sk_skb programs run in packet/softirq context where reading the
 * socket tuple is awkward, so it is stashed here.
 *
 * All addresses are stored in network byte order (matching the format expected
 * by struct gadget_l4endpoint_t). Ports are stored in host byte order.
 *
 * proc holds the owning process (and therefore its mount namespace) captured in
 * process context at connect() time. Copying it into a gadget event lets
 * Inspektor Gadget enrich the event with the container and Kubernetes metadata
 * of the process that opened the connection. It is only populated for the
 * active (client) side of a connection; for the passive (server) side the proc
 * fields are left zeroed.
 *
 * This layout MUST stay identical to the copy in pkg/sockhash/bpf/sockhash.bpf.c
 * so the framework-created maps are map-compatible with the specs declared here.
 */
struct gadget_tcp_stream_conn {
	__u8 version; // 4 or 6
	__u8 pad[3];
	__u16 sport; // local port, host byte order
	__u16 dport; // remote port, host byte order
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	struct gadget_process proc;
};

/*
 * gadget_sockhash holds the established TCP sockets the framework selected so
 * that sk_skb stream programs run on their data. It is the default map sk_skb
 * programs are attached to by Inspektor Gadget. The key is the socket cookie.
 *
 * The map instance is created and owned by the framework (see pkg/sockhash);
 * this declaration only fixes its shape (type / key / value / max_entries) so
 * the framework instance is map-compatible with it and can be injected via
 * MapReplacements.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} gadget_sockhash SEC(".maps");

/*
 * Maps socket cookie -> connection. Populated by the framework producer and
 * read by the sk_skb (receive) path via gadget_tcp_stream_lookup(). Owned by
 * the framework; declared here only for map-compatible replacement.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct gadget_tcp_stream_conn);
} gadget_tcp_stream_conns SEC(".maps");

/*
 * Connection 4-tuple, used as an alternative index into the connection table
 * for the sk_msg (send) path. sk_msg programs cannot obtain the socket cookie
 * (bpf_get_socket_cookie is not available there), but they do have the socket
 * tuple in the sk_msg_md context, so the connection is indexed by that tuple.
 *
 * Ports are host byte order, addresses network byte order -- matching the
 * fields read from both struct bpf_sock_ops and struct sk_msg_md.
 */
struct gadget_tcp_stream_tuple {
	__u8 version; // 4 or 6
	__u8 pad[3];
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

/*
 * Maps connection 4-tuple -> connection, for the sk_msg send path. Populated by
 * the framework producer and read via gadget_tcp_stream_msg_lookup(). Owned by
 * the framework; declared here only for map-compatible replacement.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct gadget_tcp_stream_tuple);
	__type(value, struct gadget_tcp_stream_conn);
} gadget_tcp_stream_tuples SEC(".maps");

/*
 * GADGET_TCP_STREAM_BUILD_TUPLE fills a gadget_tcp_stream_tuple from a context
 * that exposes the standard socket fields. struct sk_msg_md (sk_msg) shares the
 * field names and byte-order conventions used by the framework's sock_ops when
 * it wrote the tuple: local_port is host byte order, remote_port is network byte
 * order stored in a __u32 (so bpf_ntohl yields the host-order port), and
 * addresses are network byte order. Using the exact same extraction guarantees
 * the keys match.
 */
#define GADGET_TCP_STREAM_BUILD_TUPLE(ctx, t)                    \
	do {                                                     \
		__builtin_memset(&(t), 0, sizeof(t));            \
		(t).sport = (__u16)(ctx)->local_port;            \
		(t).dport = (__u16)bpf_ntohl((ctx)->remote_port); \
		if ((ctx)->family == AF_INET6) {                 \
			(t).version = 6;                         \
			__u32 *_s = (__u32 *)(t).saddr;          \
			__u32 *_d = (__u32 *)(t).daddr;          \
			_s[0] = (ctx)->local_ip6[0];             \
			_s[1] = (ctx)->local_ip6[1];             \
			_s[2] = (ctx)->local_ip6[2];             \
			_s[3] = (ctx)->local_ip6[3];             \
			_d[0] = (ctx)->remote_ip6[0];            \
			_d[1] = (ctx)->remote_ip6[1];            \
			_d[2] = (ctx)->remote_ip6[2];            \
			_d[3] = (ctx)->remote_ip6[3];            \
		} else {                                         \
			(t).version = 4;                         \
			*(__u32 *)(t).saddr = (ctx)->local_ip4;  \
			*(__u32 *)(t).daddr = (ctx)->remote_ip4; \
		}                                                \
	} while (0)

/*
 * gadget_tcp_stream_conn_to_tuple derives the tuple key for a connection from
 * the connection itself, so a gadget can correlate its own tuple-keyed state
 * across the receive path (which has a struct gadget_tcp_stream_conn from
 * gadget_tcp_stream_lookup) and the send path (which builds the tuple from the
 * sk_msg context with GADGET_TCP_STREAM_BUILD_TUPLE). It reproduces exactly what
 * that macro writes, so the keys match. The address unions in conn are
 * zero-padded beyond the v4 field, so copying all 16 bytes is correct for both
 * families.
 */
static __always_inline void
gadget_tcp_stream_conn_to_tuple(const struct gadget_tcp_stream_conn *conn,
				struct gadget_tcp_stream_tuple *t)
{
	__builtin_memset(t, 0, sizeof(*t));
	t->version = conn->version;
	t->sport = conn->sport;
	t->dport = conn->dport;
	__builtin_memcpy(t->saddr, conn->saddr_v6, sizeof(t->saddr));
	__builtin_memcpy(t->daddr, conn->daddr_v6, sizeof(t->daddr));
}

/*
 * gadget_tcp_stream_lookup returns the connection recorded for the socket this
 * skb belongs to, or NULL if the socket was not tracked.
 */
static __always_inline struct gadget_tcp_stream_conn *
gadget_tcp_stream_lookup(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	return bpf_map_lookup_elem(&gadget_tcp_stream_conns, &cookie);
}

/*
 * gadget_tcp_stream_msg_lookup is the sk_msg (send path) counterpart of
 * gadget_tcp_stream_lookup. sk_msg programs cannot read the socket cookie, so
 * the connection is looked up via its 4-tuple (recorded by the framework
 * sock_ops program) instead.
 */
static __always_inline struct gadget_tcp_stream_conn *
gadget_tcp_stream_msg_lookup(struct sk_msg_md *msg)
{
	struct gadget_tcp_stream_tuple t;
	GADGET_TCP_STREAM_BUILD_TUPLE(msg, t);
	return bpf_map_lookup_elem(&gadget_tcp_stream_tuples, &t);
}

#endif /* __GADGET_TCP_STREAM_H */
