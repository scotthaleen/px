# Historical Connectivity And Transfer Spikes

This document preserves the pre-context diagnostic spikes that established PX's
direct-only ICE and bounded transfer behavior. These commands use manually
provisioned identities and are debugging aids, not the current agent-backed user
workflow.

## Connectivity Reproduction

Generate identities and start the diagnostic signaling server:

```sh
px debug keygen --private ./tmp/a.key --public ./tmp/a.pub
px debug keygen --private ./tmp/b.key --public ./tmp/b.pub
px-server -v debug signal --listen :8090
```

Start the answering peer, then the offering peer, with the same STUN service:

```sh
px -v debug probe --signal wss://signal.example/signal \
  --stun stun:stun.l.google.com:19302 --session demo \
  --private ./tmp/b.key --peer-public ./tmp/a.pub --json

px -v debug probe --signal wss://signal.example/signal \
  --stun stun:stun.l.google.com:19302 --session demo \
  --private ./tmp/a.key --peer-public ./tmp/b.pub --offer --json
```

Google's endpoint is an external example not controlled by PX. Up to four UDP
`stun:` values are accepted; `stuns:`, `turn:`, and `turns:` are rejected. The
integrated stateless listener can be reproduced with:

```sh
px-server serve --listen 127.0.0.1:8080 --stun-listen :3478
```

Expose STUN directly over UDP or through a source-preserving load balancer, not
an HTTP tunnel. Current deployment guidance is in [STUN](../guides/stun.md) and
[Secure Rendezvous Deployment](../guides/secure-rendezvous.md).

JSON records setup `duration`, gathered and selected candidate types, and pair
addresses. Debug logs redact candidate addresses. Every real-network run should
record the environment, gathered types on both peers, selected pair, setup
latency, reconnect result, and expected failure. Candidate gathering alone is
not success; only a completed DataChannel ping/pong establishes a path.

| Environment | Availability | Gathered types | Selected pair | Setup | Reconnect | Expected failure reason |
| --- | --- | --- | --- | --- | --- | --- |
| Same-host automated protocol test | Measured | `host`, `srflx` | `host/host` | Test-dependent | Two consecutive runs pass | None; validates STUN gathering and direct ICE wiring, not NAT traversal |
| Separate home NATs | Not available in this workspace | Unmeasured | Unmeasured | Unmeasured | Unmeasured | Endpoint-dependent NAT or blocked inbound checks may prevent a pair |
| Home NAT to cloud VM | Not available in this workspace | Unmeasured | Unmeasured | Unmeasured | Unmeasured | Cloud firewall or security-group UDP policy |
| Double NAT or CGNAT | Not available in this workspace | Unmeasured | Unmeasured | Unmeasured | Unmeasured | Incompatible nested or endpoint-dependent mappings |
| VPN enabled | Not available in this workspace | Unmeasured | Unmeasured | Unmeasured | Unmeasured | VPN policy or full-tunnel UDP filtering |
| Native IPv6 peers | Not available in this workspace | Unmeasured | Unmeasured | Unmeasured | Unmeasured | Missing global IPv6 reachability or firewall policy |
| UDP blocked | Not available in this workspace | Unmeasured | Unmeasured | Unmeasured | Unmeasured | Expected direct-connect timeout because no relay is configured |

The spike forwarded bounded signed SDP and at most 32 trickled candidates in
each direction. It gathered UDP host and server-reflexive candidates only and
never relayed DataChannel bytes. Overlay interfaces and Tailscale address ranges
were rejected so they could not masquerade as measured paths. `--allow-loopback`
existed only for same-machine tests.

## Transfer Reproduction

With the diagnostic signaling server above, start the receiver first:

```sh
px -v debug receive-file \
  --signal ws://signal.example:8090/signal \
  --session transfer-demo \
  --private ./tmp/b.key \
  --peer-public ./tmp/a.pub \
  --inbox ./tmp/inbox \
  --context-name home \
  --sender laptop
```

Then start the sender:

```sh
px -v debug send-file \
  --signal ws://signal.example:8090/signal \
  --session transfer-demo \
  --private ./tmp/a.key \
  --peer-public ./tmp/b.pub \
  --source ./builds/app.tar \
  --name app.tar
```

The receiver committed `home/laptop/app.tar` beneath its opened inbox root.
Both commands reported byte count, SHA-256, duration, and selected host pair.
The spike limited files to 1 GiB and operations to 10 minutes by default. It used
32 KiB DataChannel messages, an eight-message receive queue, 256/128 KiB sender
buffer high/low watermarks, and 4 KiB control messages.

The sender opened one regular non-symlink file, hashed and rewound the same
handle, then verified while streaming. The receiver checked limits and free
space, wrote beneath `os.Root`, verified count and SHA-256, synced, and published
with an exclusive hard link. Portable-name checks and cleanup prevented escape,
overwrite, or retention of handled failed partials.

## Historical Measurement

A same-host non-loopback macOS run transferred a 22,609,106-byte `px` binary over
host candidates on the physical LAN interface. Both peers verified SHA-256
`7d994edf7b2c0dde28b7b003be2b94fb09030bb23be15f2f6607dedccb662357` and
reported approximately 255 ms of transfer-protocol time. This confirmed bounded
flow through that candidate path, not throughput between distinct machines.

`PX_TEST_REAL_LAN=1 go test -count=1 -tags=process ./testscript -run TestTransferProcesses`
reproduces the separate-process large-file test without hermetic loopback. It
requires a usable non-overlay LAN interface.
