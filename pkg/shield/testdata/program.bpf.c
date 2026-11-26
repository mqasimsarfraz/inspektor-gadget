// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} gadget_socket_denials SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} gadget_getpgid_denials SEC(".maps");

SEC("lsm/socket_create")
int BPF_PROG(gadget_shield_socket, int family, int type, int protocol, int kern,
	     int ret)
{
	if (ret)
		return ret;
	if (family == 2) {
		__u32 key = 0;
		__u64 *count =
			bpf_map_lookup_elem(&gadget_socket_denials, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
	}
	return family == 2 ? -1 : 0;
}

SEC("fmod_ret/__x64_sys_getpgid")
long BPF_PROG(gadget_shield_getpgid, const struct pt_regs *regs, long ret)
{
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&gadget_getpgid_denials, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	return -1;
}

char LICENSE[] SEC("license") = "GPL";
