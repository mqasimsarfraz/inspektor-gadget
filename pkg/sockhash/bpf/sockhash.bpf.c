// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * Framework-owned producer side of the TCP-stream plumbing (see
 * include/gadget/tcp_stream.h for the consumer side used by gadgets).
 *
 * Inspektor Gadget owns and attaches these programs and their maps, rather than
 * compiling them into each gadget's eBPF object, because they manage the
 * lifecycle of live socket references (the SOCKHASH) and of host-wide state
 * (the sock_ops attached to the cgroup v2 root). A gadget only ships the sk_skb
 * / sk_msg consumers that run on the sockets this producer selects.
 *
 *   sock_ops (cgroup v2 root)
 *     on TCP connect/established, if the socket matches gadget_tcp_stream_ports:
 *       - insert it into gadget_sockhash (so the gadget's sk_skb/sk_msg run on it)
 *       - record its 4-tuple + process info, indexed by cookie
 *         (gadget_tcp_stream_conns) and by 4-tuple (gadget_tcp_stream_tuples)
 *
 *   fexit/tcp_connect
 *     runs in the connecting process' context (where the current-task helpers
 *     are valid, unlike sock_ops) and fills conn->proc for the active side so
 *     the gadget's events can be enriched with container / Kubernetes metadata.
 *
 * Which sockets are tracked is decided at runtime by gadget_tcp_stream_ports,
 * populated from userspace (pkg/sockhash) with the ports the gadget asked for.
 * This replaces the former compile-time gadget_tcp_stream_should_track() hook,
 * which is not available once the sock_ops program lives in the framework.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h> // for BPF_PROG (fexit)
#include <bpf/bpf_core_read.h>

#include <gadget/types.h>
#include <gadget/common.h> // for gadget_process_populate()

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * These two structs are the map values shared with the gadget's sk_skb / sk_msg
 * programs. Their layout MUST stay identical to the copies in
 * include/gadget/tcp_stream.h so the framework-created maps are map-compatible
 * with the specs the gadget declares (only then can the eBPF operator inject
 * these instances via MapReplacements).
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

struct gadget_tcp_stream_tuple {
	__u8 version; // 4 or 6
	__u8 pad[3];
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

/* Established TCP sockets selected for tracking. Key: socket cookie. */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} gadget_sockhash SEC(".maps");

/* socket cookie -> connection (receive/sk_skb path). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct gadget_tcp_stream_conn);
} gadget_tcp_stream_conns SEC(".maps");

/* connection 4-tuple -> connection (send/sk_msg path). */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct gadget_tcp_stream_tuple);
	__type(value, struct gadget_tcp_stream_conn);
} gadget_tcp_stream_tuples SEC(".maps");

/*
 * Ports the gadget asked to track, host byte order. Populated from userspace.
 * A socket is tracked if either its local or remote port is present here. Sized
 * to the whole port space so any set of ports fits; it is a plain HASH so only
 * the ports actually inserted consume memory.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} gadget_tcp_stream_ports SEC(".maps");

// gadget_tcp_stream_tracked reports whether a socket with the given host-order
// ports should be tracked, i.e. either endpoint's port was requested by the
// gadget. This lets us catch both the client side (remote port matches, e.g.
// the DNS server's :53) and the server side (local port matches).
static __always_inline bool gadget_tcp_stream_tracked(__u16 sport, __u16 dport)
{
	if (bpf_map_lookup_elem(&gadget_tcp_stream_ports, &sport))
		return true;
	if (bpf_map_lookup_elem(&gadget_tcp_stream_ports, &dport))
		return true;
	return false;
}

static __always_inline void
gadget_tcp_stream_fill_conn(struct bpf_sock_ops *skops,
			    struct gadget_tcp_stream_conn *conn)
{
	// local_port is host byte order; remote_port is a __be16 whose value ends
	// up in the high 16 bits of the __u32 context field, so bpf_ntohl() (not
	// bpf_ntohs()) yields the host-order port.
	conn->sport = (__u16)skops->local_port;
	conn->dport = (__u16)bpf_ntohl(skops->remote_port);

	if (skops->family == AF_INET6) {
		conn->version = 6;
		__u32 *saddr = (__u32 *)conn->saddr_v6;
		__u32 *daddr = (__u32 *)conn->daddr_v6;
		// Copy each word individually: the verifier only allows
		// fixed-offset scalar loads from the sock_ops context, not a
		// memcpy over it.
		saddr[0] = skops->local_ip6[0];
		saddr[1] = skops->local_ip6[1];
		saddr[2] = skops->local_ip6[2];
		saddr[3] = skops->local_ip6[3];
		daddr[0] = skops->remote_ip6[0];
		daddr[1] = skops->remote_ip6[1];
		daddr[2] = skops->remote_ip6[2];
		daddr[3] = skops->remote_ip6[3];
	} else {
		conn->version = 4;
		conn->saddr_v4 = skops->local_ip4; // already network byte order
		conn->daddr_v4 = skops->remote_ip4;
	}
}

// gadget_tcp_stream_conn_to_tuple derives the tuple key for a connection from
// the connection itself. The address unions in conn are zero-padded beyond the
// v4 field, so copying all 16 bytes is correct for both families.
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

// gadget_tcp_stream_record stores the connection under both indexes: by socket
// cookie (used by the sk_skb receive path) and by 4-tuple (used by the sk_msg
// send path, which cannot obtain the cookie).
static __always_inline void
gadget_tcp_stream_record(struct bpf_sock_ops *skops, __u64 cookie)
{
	struct gadget_tcp_stream_conn conn = {};
	gadget_tcp_stream_fill_conn(skops, &conn);
	bpf_map_update_elem(&gadget_tcp_stream_conns, &cookie, &conn, BPF_ANY);

	struct gadget_tcp_stream_tuple t;
	gadget_tcp_stream_conn_to_tuple(&conn, &t);
	bpf_map_update_elem(&gadget_tcp_stream_tuples, &t, &conn, BPF_ANY);
}

SEC("sockops")
int gadget_tcp_stream_sockops(struct bpf_sock_ops *skops)
{
	if (skops->family != AF_INET && skops->family != AF_INET6)
		return 0;

	__u16 sport = (__u16)skops->local_port;
	__u16 dport = (__u16)bpf_ntohl(skops->remote_port);
	if (!gadget_tcp_stream_tracked(sport, dport))
		return 0;

	__u64 cookie = bpf_get_socket_cookie(skops);

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB: {
		// Record the connection tuple for the active (client) side and
		// assign the socket cookie. The owning process cannot be captured
		// here: sock_ops programs are not allowed to call the
		// bpf_get_current_*() helpers, even though this callback runs in
		// the connecting process' context. The companion fexit/tcp_connect
		// program below fills in conn->proc using the same cookie.
		//
		// The socket is not established yet, so it is not added to the
		// sockhash here; that happens at *_ESTABLISHED_CB below.
		gadget_tcp_stream_record(skops, cookie);
		return 0;
	}
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		// If the connection was not already recorded at connect time (i.e.
		// the passive/server side, which has no connect callback), record
		// it now. The proc fields stay zeroed for the passive side because
		// establishment happens in softirq context.
		if (!bpf_map_lookup_elem(&gadget_tcp_stream_conns, &cookie))
			gadget_tcp_stream_record(skops, cookie);

		// Add the socket to the sockhash so sk_skb stream programs run on
		// its data.
		bpf_sock_hash_update(skops, &gadget_sockhash, &cookie,
				     BPF_NOEXIST);
		return 0;
	default:
		return 0;
	}
}

/*
 * gadget_tcp_stream_connect captures the process that opened an active (client)
 * connection so its container / Kubernetes metadata can enrich the events
 * produced by the sk_skb program. It runs on the return of tcp_connect(), i.e.
 * still in the connecting process' syscall context (so bpf_get_current_*() is
 * valid) and after the sock_ops TCP_CONNECT_CB above has already recorded the
 * connection and assigned the socket cookie. We correlate the two via that
 * cookie, read here from sk->sk_cookie.
 *
 * This only covers the active (client) side. Passive (server) sockets have no
 * connect() call in process context, so their conn->proc is left zeroed.
 */
SEC("fexit/tcp_connect")
int BPF_PROG(gadget_tcp_stream_connect, struct sock *sk, int ret)
{
	if (ret != 0)
		return 0;

	__u64 cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
	if (cookie == 0)
		return 0;

	struct gadget_tcp_stream_conn *conn =
		bpf_map_lookup_elem(&gadget_tcp_stream_conns, &cookie);
	if (!conn)
		return 0; // socket not tracked

	gadget_process_populate(&conn->proc);

	// Mirror the populated process info into the tuple-indexed copy used by
	// the sk_msg send path, so both lookup paths return identical enrichment.
	struct gadget_tcp_stream_tuple t;
	gadget_tcp_stream_conn_to_tuple(conn, &t);
	bpf_map_update_elem(&gadget_tcp_stream_tuples, &t, conn, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
