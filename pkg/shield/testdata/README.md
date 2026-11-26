# Native IG-Shield fixture

`mitigation.bee` is a built, signed Shirudo BPF v1 package, produced with
`shirudo-dev/shirudo` revision `0c38db71`'s native builder. It contains an LSM
`socket_create` hook and an x86-64 fmod_ret `getpgid` hook from `program.bpf.c`,
with two private single-entry counter maps, plus the native paired unload
directive and public certificate. The ephemeral
ML-DSA signing private key is not included.

**Do not run this mitigation on a shared host:** it denies IPv4 socket creation
and `getpgid` host-wide. Parser and inspection tests do not attach it.

To regenerate, compile `program.bpf.c` with clang's `-target bpf -O2 -g`,
Shirudo's generated `vmlinux.h` and libbpf headers. In a separate working
directory place the resulting `program.bpf.o` beside this Beefile:

```toml
[package]
name = "ig-shield-probe"
description = "Isolated VM mitigation and cleanup test"
license = "GPL-2.0"

[[upatches]]
source = "program.bpf.o"
```

Use the native builder's `shirudo-build bpm build . --version 1.0.0 --keys-dir
KEYS`, with an ephemeral ML-DSA-87 key and DER certificate as required by that
builder (OpenSSL 3.5 or newer). Copy the resulting built archive to
`mitigation.bee`, then discard the private key. This is fixture maintenance, not
a requirement for IG-Shield users with existing built packages.

The functional test is disabled by default. In an **isolated disposable
x86-64 VM**, boot a kernel with BPF LSM enabled and with
`lsm=capability,bpf ig_shield_test_vm` in its command line, then run:

```bash
IG_SHIELD_TEST_VM=1 go test -v -run TestMitigationsVM ./pkg/shield
```

It verifies application, cleanup, failed-start rollback, FD counts and
independent run ownership. It has been exercised on stock Ubuntu Linux
6.8.0-149-generic without Shirudo initialization.
