// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/types.h>

// Number of raw RESP bytes captured per message. Enough to hold a command verb
// plus its key (and short error replies), which is what troubleshooting cares
// about; the value payload of e.g. a SET is intentionally not captured. Keep it
// a power of two so the sk_msg copy loop below stays cheap for the verifier.
#define REDIS_MAX_DATA 256

// Redis (RESP) is carried over TCP on port 6379 by default. Only connections
// whose port matches are tracked; the framework's sock_ops applies that filter
// based on the ports configured for the Sockhash operator (see the
// "operator.Sockhash.tcp-stream-ports" default in gadget.yaml). Because the
// framework owns the sock_ops program, the former compile-time
// gadget_tcp_stream_should_track() hook is no longer used here.
//
// Tracking the Redis port catches the active (client) side connecting to a
// Redis server: on such sockets sk_msg observes commands the client sends and
// sk_skb observes replies it receives. This matches the enrichment model of
// <gadget/tcp_stream.h>, which only populates conn->proc for the active side.

#include <gadget/tcp_stream.h>
#include <gadget/filter.h>

// Direction of a captured message. Stored in a plain __u8 (not an enum-typed
// field) on purpose: an enum-typed *_raw field would be auto-formatted into a
// "type" string using the C enumerator names. We want the friendlier
// "command"/"reply" strings, which the WASM module sets instead.
enum redis_type {
	// Command sent by the client to the server (observed on the send path).
	redis_command = 0,
	// Reply sent by the server back to the client (observed on the
	// receive path).
	redis_reply = 1,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc; // enables container/k8s enrichment
	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;
	__u8 type_raw; // enum redis_type
	// Time between a command being sent and its reply being received on the
	// same connection. Only set on reply events; 0 otherwise (and 0 when no
	// matching command was recorded).
	gadget_duration latency_ns_raw;
	// data_len is the full length of the RESP message; data holds only its
	// first REDIS_MAX_DATA bytes (see REDIS_MAX_DATA above). The RESP parsing
	// into command/key/args/reply/error happens in the WASM module.
	__u32 data_len;
	__u8 data[REDIS_MAX_DATA];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(redis, events, event);

// Records, per connection, the timestamp of the last command sent so the reply
// path can compute the round-trip latency. Keyed by the same 4-tuple used by
// <gadget/tcp_stream.h>: the send path (sk_msg) builds it from the sk_msg
// context, and the receive path (sk_skb) derives the identical tuple from the
// connection recorded by sock_ops, so the keys match. An LRU map bounds memory
// and transparently drops entries for connections whose reply was never seen.
// This tracks a single in-flight command per connection, which fits Redis'
// usual synchronous request/response pattern; with pipelining the latency is
// attributed approximately (to the most recent command).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct gadget_tcp_stream_tuple);
	__type(value, __u64);
} redis_inflight SEC(".maps");

// Applies the standard Inspektor Gadget filters (-c/--containername, --podname,
// --pid, --uid, --comm, ...) using the process captured at connect() time in
// conn->proc. Only the active (client) side has a populated conn->proc, which is
// exactly the side we track, so a filtered-out connection is correctly dropped.
static __always_inline bool should_discard(struct gadget_tcp_stream_conn *conn)
{
	struct gadget_process *p = &conn->proc;
	return gadget_should_discard_data(p->mntns_id, p->pid, p->tid, p->comm,
					  p->creds.uid, p->creds.gid);
}

static __always_inline void fill_conn(struct event *event,
				      struct gadget_tcp_stream_conn *conn,
				      enum redis_type type, __u32 data_len)
{
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->proc = conn->proc; // container/k8s enrichment
	event->type_raw = type;
	event->data_len = data_len;
	event->latency_ns_raw = 0; // overridden on the reply path when known

	// gadget_reserve_buf() does not zero the buffer, so clear the endpoints
	// fully (including the unused bytes of the address union and any padding)
	// before setting the fields we care about.
	__builtin_memset(&event->src, 0, sizeof(event->src));
	__builtin_memset(&event->dst, 0, sizeof(event->dst));
	event->src.version = event->dst.version = conn->version;
	event->src.proto_raw = event->dst.proto_raw = IPPROTO_TCP;
	event->src.port = conn->sport;
	event->dst.port = conn->dport;
	if (conn->version == 6) {
		__builtin_memcpy(event->src.addr_raw.v6, conn->saddr_v6, 16);
		__builtin_memcpy(event->dst.addr_raw.v6, conn->daddr_v6, 16);
	} else {
		event->src.addr_raw.v4 = conn->saddr_v4;
		event->dst.addr_raw.v4 = conn->daddr_v4;
	}
}

// Observe replies received by the client. The verdict runs on the reassembled,
// in-order TCP stream. Because this gadget has no sk_skb/stream_parser, the
// verdict is invoked on whatever in-order bytes TCP just made available, which
// for a large reply (e.g. a big array) can be several segments. To emit exactly
// one event per reply -- the segment that starts the reply, whose leading bytes
// are parseable -- we only report a reply that matches an outstanding command
// recorded by the send path (redis_inflight). The first segment consumes that
// entry; later continuation segments of the same reply find no match and are
// skipped. As a side effect, server-initiated data with no preceding command on
// the connection (e.g. RESP3 push / pub-sub messages) is not reported.
SEC("sk_skb/stream_verdict")
int ig_redis_reply(struct __sk_buff *skb)
{
	if (skb->len == 0)
		return SK_PASS;

	struct gadget_tcp_stream_conn *conn = gadget_tcp_stream_lookup(skb);
	if (!conn)
		return SK_PASS; // socket not tracked
	if (should_discard(conn))
		return SK_PASS; // filtered out (e.g. different container)

	// Only emit for the first segment of a reply, i.e. one that matches an
	// outstanding command. Consume the entry so continuation segments of the
	// same reply (which carry no leading RESP type byte) are skipped.
	struct gadget_tcp_stream_tuple t;
	gadget_tcp_stream_conn_to_tuple(conn, &t);
	__u64 *sent = bpf_map_lookup_elem(&redis_inflight, &t);
	if (!sent)
		return SK_PASS; // continuation fragment or unsolicited data
	__u64 sent_ts = *sent;
	bpf_map_delete_elem(&redis_inflight, &t);

	struct event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return SK_PASS;

	__u32 len = skb->len;
	if (len > REDIS_MAX_DATA)
		len = REDIS_MAX_DATA;
	if (len == 0) {
		// Cannot happen (skb->len != 0 above) but proves to the verifier
		// that the load below is a non-zero-sized read.
		gadget_discard_buf(event);
		return SK_PASS;
	}
	__builtin_memset(event->data, 0, sizeof(event->data));
	if (bpf_skb_load_bytes(skb, 0, event->data, len)) {
		gadget_discard_buf(event);
		return SK_PASS;
	}

	fill_conn(event, conn, redis_reply, skb->len);
	if (sent_ts && event->timestamp_raw > sent_ts)
		event->latency_ns_raw = event->timestamp_raw - sent_ts;

	gadget_submit_buf(skb, &events, event, sizeof(*event));
	return SK_PASS;
}

// Observe commands the client sends. sk_msg has no stream parser, so it sees one
// sendmsg at a time; a single Redis command comfortably fits in one write.
SEC("sk_msg")
int ig_redis_command(struct sk_msg_md *msg)
{
	if (msg->size == 0)
		return SK_PASS;

	struct gadget_tcp_stream_conn *conn = gadget_tcp_stream_msg_lookup(msg);
	if (!conn)
		return SK_PASS;
	if (should_discard(conn))
		return SK_PASS;

	// Linearize the leading bytes so they can be read via data/data_end.
	__u32 pull = msg->size;
	if (pull > REDIS_MAX_DATA)
		pull = REDIS_MAX_DATA;
	if (bpf_msg_pull_data(msg, 0, pull, 0))
		return SK_PASS;

	__u8 *data = (__u8 *)(long)msg->data;
	__u8 *data_end = (__u8 *)(long)msg->data_end;

	struct event *event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return SK_PASS;

	__builtin_memset(event->data, 0, sizeof(event->data));
	// Bounded byte copy: sk_msg payloads are not a contiguous helper-copyable
	// buffer like an sk_buff, so copy through the verified data/data_end
	// pointers one byte at a time up to REDIS_MAX_DATA.
	for (int i = 0; i < REDIS_MAX_DATA; i++) {
		if (data + i + 1 > data_end)
			break;
		event->data[i] = data[i];
	}

	fill_conn(event, conn, redis_command, msg->size);

	// Record the send time for this connection so the reply path can compute
	// latency. A failed update (map full) only costs a latency sample, not a
	// visible event, so it is best-effort.
	struct gadget_tcp_stream_tuple t;
	GADGET_TCP_STREAM_BUILD_TUPLE(msg, t);
	bpf_map_update_elem(&redis_inflight, &t, &event->timestamp_raw, BPF_ANY);

	gadget_submit_buf(msg, &events, event, sizeof(*event));
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
