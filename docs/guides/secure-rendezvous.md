# Secure Rendezvous Deployment

This deployment runs one `px-server` behind Caddy. Caddy accepts HTTPS and WSS
on TCP 443 and forwards HTTP and WebSocket traffic to a loopback listener. The
optional PX STUN listener remains direct UDP because an HTTP reverse proxy
cannot preserve the address that STUN must reflect.

This is a single-server topology. It does not add automatic ACME, TURN, a public
administrative API, or multi-replica coordination.

## Prerequisites

- A host where `px.example` resolves to the public address.
- A certificate and private key for `px.example`, provisioned by an external
  certificate process.
- Caddy installed as a supervised service and a verified `px-server` binary.
- A private, persistent directory for `PX_HOME` owned by a dedicated PX service
  account.

## Prepare The Host

On Linux, create a non-login `px` service account and its persistent directory.
The account-management command varies by operating system. Install the verified
binary and enforce the persistent directory ownership and mode:

```console
sudo install -d -o px -g px -m 0700 /var/lib/px
sudo install -o root -g root -m 0755 ./px-server /usr/local/bin/px-server
```

Restrict `/var/lib/px` to the PX service account. The server database is
`/var/lib/px/server/state.db`; SQLite also uses WAL sidecars while running. The
authority private key is `/var/lib/px/server/authority/authority.key`, with
`server.pub` beside it. After initialization, verify that `/var/lib/px`,
`server`, `authority`, and `run` are owned by `px:px` and mode `0700`, and that
`authority.key` is owned by `px:px` and mode `0600`. `server.pub` may be `0644`
but must not be writable by other users. Do not give the Caddy account access to
the PX group or home.

Choose exactly one start procedure below. Do not run the foreground and systemd
server against the same PX home at the same time.

### Manual Foreground Smoke

For a disposable smoke test or initial inspection, initialize the fresh home
once, then run the backend in the foreground:

```console
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server init
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server serve \
  --listen 127.0.0.1:8080 \
  --trusted-proxy 127.0.0.1/32
```

Stop it with `Ctrl-C`, or from another shell with the protected local command:

```console
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server stop
```

Wait for the foreground process to exit before starting supervision. When
transitioning this same initialized home to systemd, skip the `init` step in the
supervised procedure because `px-server init` intentionally refuses overwrite.

### Supervised Service

For a fresh supervised home, initialize once and install this complete unit. If
the manual procedure already initialized the same stopped home, skip `init`:

```console
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server init
sudo tee /etc/systemd/system/px-server.service >/dev/null <<'EOF'
[Unit]
Description=PX rendezvous server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=px
Group=px
Environment=PX_HOME=/var/lib/px
WorkingDirectory=/var/lib/px
UMask=0077
ExecStart=/usr/local/bin/px-server serve --listen 127.0.0.1:8080 --trusted-proxy 127.0.0.1/32
ExecStop=/usr/local/bin/px-server stop
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now px-server.service
sudo systemctl status px-server.service
```

This machine-level rendezvous unit is separate from `px startup install`, which
manages only a user's local agent. The tracked
[`px-server.service`](../examples/px-server.service) contains the same unit for
source-repository maintenance; release archive users need only the inline unit.

The unit declares network-online ordering, runs as the dedicated `px` user with
`PX_HOME=/var/lib/px` and umask `0077`, restarts only after failure, sends stdout
and stderr to the journal, and requests protected-IPC shutdown before systemd's
30-second stop bound. Inspect logs with `journalctl -u px-server.service`. Edit
the executable, home, listen address, trusted proxy, and optional `--stun-listen`
for the deployment, then run `systemctl daemon-reload` and restart the unit.
Other supervisors must preserve the same dedicated identity, persistent home,
private umask, restart policy, captured logs, and graceful protected-IPC stop path.

The unit intentionally has no ordering dependency on Caddy: both services may
start after the network, and Caddy's active backend health check keeps an
unready PX backend out of service. Keep the TLS private key owned and readable
only by the Caddy service account. Use [`examples/Caddyfile`](../examples/Caddyfile)
as the Caddy configuration. It uses externally managed certificate files and a
neutral `px.example` origin. Caddy supports WebSocket upgrade without manual
header rules; its bounded setup timeouts and unlimited stream timeout permit
long-lived WSS sessions. Validate the configuration with the installed Caddy
version before loading it. Allow inbound TCP 443 and deny public TCP 8080.

## Trusted Proxy Addresses And Rate Limits

PX does not trust `Forwarded` or `X-Forwarded-For` by default. Each repeatable
`--trusted-proxy CIDR` names an immediate proxy network allowed to supply those
headers; at most 16 CIDRs are accepted. The example trusts only Caddy's IPv4
loopback address. Do not configure broad client, LAN, container, or public
network ranges merely to make forwarding work.

The example Caddyfile overwrites `X-Forwarded-For` with the direct TLS client's
address and removes `Forwarded`. PX validates bounded address chains and walks
from the immediate peer toward the client, selecting the rightmost untrusted
hop. If both headers are present they must resolve to the same client. PX rejects
malformed, conflicting, oversized, or overlong chains. Headers from an
untrusted immediate peer are ignored. The five-per-minute PX enrollment limit
therefore remains per client in this topology. Configure additional edge
request and connection controls when the deployment's abuse model requires
them.

## Health And Startup

`GET /livez` is unconditional HTTP-handler liveness and returns an empty HTTP
204 while the handler can serve. `GET /readyz` is load-balancer readiness. It
returns an empty HTTP 204 only after the PX lifecycle readiness gate opens, the
HTTP listener is ready, and a short non-mutating database count succeeds;
otherwise it returns an empty HTTP 503. The example uses readiness for Caddy's
active backend health check:

```console
curl --fail --silent --show-error https://px.example/readyz -o /dev/null
```

To prevent unauthenticated health traffic from queueing SQLite work, PX caches
each readiness database result for two seconds and permits at most one 250 ms
probe at a time. Requests use a fresh cached result. Once it expires, one
request performs the probe and concurrent requests fail closed with 503 until
that result is available. Successful and failed results use the same TTL, so
continued checks expose database degradation or recovery within at most 2.25
seconds. A false lifecycle gate overrides the cache immediately during startup
and shutdown. The request-triggered probe starts no background goroutine.

Both responses are empty and disclose no operational details. `/readyz` does
not validate external reachability, inspect the optional STUN listener, or prove
that two peers can connect. Use the supervised status and audit commands below
for bounded process health and redacted administrative history, and `px doctor`
after enrollment for context, STUN, and peer diagnostics. Do not use `/livez`
for load-balancer admission.

## Certificates And Identity

Renew certificates with the external certificate process, atomically replace
the files referenced by the Caddyfile, and validate and reload Caddy. PX agents
use normal TLS hostname and certificate-chain verification; do not disable it.
An existing WebSocket may survive a delayed reload or reconnect, while every
new TLS connection receives the current certificate.

For a private test CA that is not in the operating-system trust store, set
`PX_CA_FILE` on the agent to a private PEM trust bundle. PX starts with the
system certificate pool and appends this bundle for HTTPS and WSS. An unreadable
file or a file with no valid certificates fails agent startup; PX never enables
insecure verification. Publicly trusted certificates normally require no
`PX_CA_FILE`.

TLS authenticates `px.example`. PX separately pins the rendezvous authority ID
when a context is created and verifies later enrollment credentials and WSS
challenges against it. After client authentication, PX also requires a final
authority signature bound to that challenge, device identity, membership
revision, and client proof before installing the WSS control connection. This
prevents an impostor from completing authentication with a fresh signed
challenge obtained from the real server. Certificate renewal does not rotate
the PX authority.

Back up the entire stopped `PX_HOME`, including `state.db`, its possible WAL
sidecars, `authority.key`, and `server.pub`. Also keep an encrypted, access-
controlled off-host backup of the authority directory. Test restoration. Loss
or replacement of the authority key changes the server identity and prevents
existing contexts and credentials from authenticating; restoring only SQLite
without its matching authority is not a recovery.

## Administration, Logs, And Failure

Supervised administration must use the service identity, exact PX home, and
installed binary:

```console
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server status
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server devices pending
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server devices approve F7K2-M9Q4
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server audit list
sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server stop
```

These commands use the protected local socket under `/var/lib/px/run`. Its Unix
peer check requires the same effective UID as the running server; invoking the
CLI as root or another account does not satisfy that boundary merely because it
can name the socket. Do not proxy or expose the socket, or mount it into Caddy.
The manual foreground smoke commands above already use the same `px` identity
and home. For supervised shutdown, prefer `systemctl stop` as described below;
the unit runs the final command above with `User=px` and `PX_HOME=/var/lib/px`.

Capture Caddy's JSON access log from stderr with the service supervisor. It may
contain client addresses and request metadata, so restrict access and set a
retention policy. Capture `px-server` stderr separately. PX operational logs do
not intentionally include credentials, private keys, enrollment codes, or
forwarded client-address headers; avoid adding proxy headers to application
logs.

For supervised planned shutdown, stop admitting new edge traffic and run
`sudo systemctl stop px-server.service`; systemd invokes the protected
`ExecStop` command under the unit's service identity and home. Stop a manual
foreground server with `Ctrl-C`. PX closes active presence sessions during
graceful shutdown. Agents mark the context disconnected and retry with bounded
backoff.
If the backend crashes or becomes unreachable, Caddy returns a gateway error
for new requests and existing WSS sessions close; agents continue retrying.
Supervise both processes and alert on repeated failures. Do not run a second PX
replica against this SQLite database or rely on proxy stickiness.

## Optional Direct STUN

To host PX STUN on the same machine, add `--stun-listen 0.0.0.0:3478` to the
single selected server command. For foreground smoke, append it to the manual
`serve` command above. For systemd, edit only the existing `ExecStart` line:

```ini
ExecStart=/usr/local/bin/px-server serve --listen 127.0.0.1:8080 --trusted-proxy 127.0.0.1/32 --stun-listen 0.0.0.0:3478
```

Then run `sudo systemctl daemon-reload` and `sudo systemctl restart
px-server.service`. Do not start a second `px-server` process for STUN.

Allow UDP 3478 directly or through a source-address-preserving UDP load
balancer, then configure `stun:stun.px.example:3478`. Do not route UDP through
Caddy's HTTP reverse proxy. The stateless listener has no health endpoint of
its own; test it with `px doctor --context CONTEXT`. Apply network-level abuse
controls. STUN is optional, is not TURN, and never relays transfer data.

## Verification

1. Request `https://px.example/readyz` and expect HTTP 204. Request `/livez`
   separately only when testing handler liveness semantics.
2. Run `px onboard https://px.example ...` and approve the code with
   `sudo -u px env PX_HOME=/var/lib/px /usr/local/bin/px-server devices approve CODE`.
3. Run `px doctor --context CONTEXT`; if STUN is configured, confirm `srflx`.
4. Run `px devices list` to verify authenticated WSS member operations.
5. Run `sudo systemctl restart px-server.service` and confirm the context
   disconnects and reconnects.
6. Run `px doctor --context CONTEXT --peer PEER`, then a direct send between two
   enrolled peers. The reverse proxy carries signaling only; peer diagnostics
   and transfer data use the direct peer path.

Automated tests cover the proxy topology, certificate verification, authority
pinning, authenticated WSS operation, backend failure, reconnect, and the direct
encrypted transfer path. They do not prove live Caddy operation, certificate
renewal, public NAT behavior, source-reflexive STUN, or a direct transfer through
the deployed TLS edge. Those remain manual deployment verification in the
[native validation campaign](../validation/native.md).
