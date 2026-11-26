---
title: IG-Shield
sidebar_position: 725
description: Run built Shirudo bee mitigations through verified IG images
---

IG-Shield packages existing **built `.bee` archives** inside IG OCI images.
The dedicated `shield` image operator executes their existing BPF syscall
loaders and owns the resulting LSM/fmod_ret attachments for the duration of
`ig run`. No source conversion, recompilation, Shirudo initialization, TPM
setup or kernel signing-key enrollment is needed.

## Build, sign and run

Place a built package and descriptive metadata in a directory:

```text
shield/
  mitigation-1.0.0.bee
  build.yaml
  gadget.yaml
```

`build.yaml`:

```yaml
ebpfsource: ""
metadata: gadget.yaml
shield:
  package: mitigation-1.0.0.bee
```

`gadget.yaml`:

```yaml
name: mitigation
description: Describe exactly which vulnerable operations this package denies
```

Build and publish:

```bash
sudo ig image build shield -t ghcr.io/your-org/shield:1.0.0
sudo ig image push ghcr.io/your-org/shield:1.0.0
cosign sign --key cosign.key ghcr.io/your-org/shield@sha256:IMAGE_DIGEST
sudo ig run --verify-image=true --public-keys="$(cat cosign.pub)" \
  ghcr.io/your-org/shield@sha256:IMAGE_DIGEST
```

Use your image's actual digest. Configure the trusted public key using
[IG image verification](../reference/verify-gadgets.mdx); notation is supported
as well. Verification is **mandatory**, including inspection:
`--verify-image=false`, missing signatures and unverified custom ORAS targets
are rejected. Verification and payload reads use the same immutable image
digest. Native artifact signatures remain unchanged but are not independently
verified or enrolled by IG-Shield; IG authenticates the entire enclosing image.

Building only validates and embeds the original package bytes. It does not
execute Beefile recipes, compile anything or start a builder container.
The image has one package layer and one platform, the packaging machine's
architecture. Package authors must ensure their precompiled target symbols and
CO-RE requirements match that platform and the destination kernel.

## Compatibility

The first version supports **standalone local Linux `ig` only**, BPF v1 load
artifacts with paired unload directives, private maps, and one or more
LSM/fmod_ret attach programs. A `.bee` must be a built gzip/ustar package;
a textual `.bee` Beefile recipe is not a built package.

The entire package is rejected if its executable artifacts use Java, shared
policy/labels, decoders, serializer/test-run roles, unsupported section formats
or other attachment types. Generic kind-0 attachment metadata is accepted only
when the loaded program is actually LSM. Runtime patch parameters and
metadata-defined programs, datasources and params are unsupported.
eBPF/WASM payloads and metadata generation cannot be mixed into a shield image.
Shirudo fleet selectors, persistence, upgrades and direct native package OCI
references are not implemented.

Archives are bounded to 4096 members and 256 MiB of file content;
individual `.upatch` artifacts are limited to 16 MiB and 64 maps. The loader's
context must fit in 65535 bytes. Package expansion, paths, duplicate entries,
payload digests and load/unload pairing are validated before execution.

The host needs BTF, privileges to load BPF, `BPF_PROG_TYPE_SYSCALL` and its
generated-loader helpers, the patch's target symbols, and the required
LSM/fmod_ret support. LSM packages also need `CONFIG_BPF_LSM=y` and `bpf` in the
active LSM list. Stock Ubuntu Linux **6.8.0-149-generic** has been tested with
both types without Shirudo initialization; this is not a guarantee that every
6.8 configuration or every package works. See
[kernel requirements](../reference/requirements.md#ig-shield).

## Lifetime and trust boundary

**Mitigations can affect the entire host**, including IG and unrelated
workloads. Container/namespace output filters do not scope shield hooks.
Inspect and test trusted packages in a disposable VM before production use.
IG-Shield logs applied patch names and payload digests; it produces no event
datasource.

Ctrl-C, timeout, normal shutdown and failed startup close IG's owned links,
programs and maps. Unload directives are checked for matching identity but
their loaders are not executed, avoiding deletion of another run's state.
There are no persistent pins. Closing one run removes only its attachments.

Applying several programs is not kernel-atomic: earlier hooks can become
active before later ones attach, and failure rollback also has a window.
Signature verification establishes publisher trust, not patch correctness or
safe behavior; a signed loader is privileged executable code.

IG-Shield is deliberately **not Shirudo's root-resistant enforcement**.
Root can interfere with IG or load other programs. It does not provide
Shirudo's measured admission, TPM persistence or enforced runtime policy, and
does not bypass an enforcing Shirudo kernel's own admission requirements.
