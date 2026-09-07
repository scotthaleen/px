# STUN Setup

PX uses STUN to discover the public UDP address assigned to an agent so ICE can
attempt a direct connection. STUN carries no file data and is not a relay. It
improves connectivity through many NATs but cannot bypass blocked UDP or every
NAT and firewall policy.

## Quick Start With Google

New contexts created by `px onboard` or `px join` use Google's public STUN
endpoint when no STUN option is supplied:

```console
px onboard https://px.example --context home
```

The equivalent `join` option is:

```console
px join https://px.example --context home --name laptop \
  --offered-root ./shared --inbox-root ./inbox
```

Google operates this service, not PX. Its availability and operating policy are
outside PX's control, and the service necessarily observes the source address
of each STUN request. It still does not receive signaling messages or transfer
contents. Use an endpoint whose operator and service expectations are suitable
for the deployment.

Use `--no-stun` during onboarding or join for LAN-only/private operation. Use
one or more explicit `--stun` options to replace the creation default. Existing
contexts are never migrated to Google automatically; their persisted empty or
custom ordered list remains unchanged when enrollment is resumed.

## Self-Hosted STUN

For the complete HTTPS/WSS reverse-proxy topology and its separate direct UDP
path, see [Secure Rendezvous Deployment](secure-rendezvous.md).

`px-server` includes an optional stateless STUN Binding listener:

```console
px-server serve --listen 127.0.0.1:8080 --stun-listen :3478
```

Expose UDP port 3478 directly or through a source-address-preserving load
balancer, publish a suitable DNS name, and configure each context with it:

```console
px onboard https://px.example --context home \
  --stun stun:stun.px.example:3478
```

An HTTP or HTTPS tunnel cannot expose the UDP listener. The supported
self-hosted procedure runs the stateless listener in the same supervised
`px-server` process as rendezvous. Do not start a second `px-server` against the
same PX home. Its architectural independence permits an external STUN service
or a future separately managed deployment, but those are not a second current
PX-server procedure. Protect a public listener against reflection abuse with
appropriate network-level controls.

Up to four UDP `stun:` URLs may be configured. PX intentionally rejects
`stuns:`, `turn:`, and `turns:` URLs and never silently relays file traffic.

Replace the complete ordered list after enrollment, or clear it:

```console
px context configure home \
  --stun stun:first.example:3478 \
  --stun stun:second.example:3478
px context configure home --clear-stun
```

Replacement is transactional: invalid URLs or more than four entries leave the
prior ordered list unchanged. For an enabled context, a changed STUN list then
cancels its current control/direct sessions and reconnects only that context so
future ICE gathering cannot use stale values. An operation active at that
moment may report cancellation and can be retried; other contexts are not
restarted. Root-only configuration changes do not reconnect.

## Verify

After both contexts connect, verify server-reflexive candidate gathering and a
selected direct route:

```console
px doctor --context home
px doctor --context home --peer vm
```

The context check should report `srflx` gathering. The peer check reports the
selected candidate types and addresses; candidate gathering alone does not
prove that a direct path can be established.

Selected addresses can expose public IPs, private topology, VPNs, and stable
IPv6 identifiers. Keep this explicit diagnostic private or redact it before
sharing. Routine logs do not include those addresses.
