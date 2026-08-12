# docker-api-gateway

Expose a **read-only slice** of the Docker Engine API over the network, to a client
that is not on the host.

Two endpoints are reachable and nothing else:

| method | path | why |
|---|---|---|
| `GET` | `/containers/json` | container list — names, images, state |
| `GET` | `/containers/{id}/logs` | logs, including `follow=1` streaming |

Plus `GET /healthz`, unauthenticated, which returns `ok` and does **not** touch the
Docker socket.

## Why an allowlist and not just a token

Because `GET /containers/{id}/json` — plain Docker inspect — returns `Config.Env`.

On the container that motivated this, that is **157 environment variables including
`SERVER_PASSWORD` and `ADMIN_PASSWORD`**. A read-only socket proxy still exposes
them, and so does any gateway that authenticates but proxies everything.

The container list carries no `Env`, which is what makes the two separable. Blocking
inspect at the gateway means **a leaked token still cannot reach those credentials**.
That property is asserted by tests, not just intended.

`POST` is rejected outright, so container lifecycle actions (`restart`, `stop`,
`kill`) are unavailable by design. If you need those, this is the wrong tool.

## Configuration

| | |
|---|---|
| `GATEWAY_TOKEN` (env, **required**) | bearer token; requests need `Authorization: Bearer <token>` |
| `-socket` | Docker socket path (default `/var/run/docker.sock`) |
| `-addr` | listen address (default `:9375`) |
| `-tls-cert`, `-tls-key` | enable HTTPS; omit both to serve plaintext |

Without `-tls-cert`/`-tls-key` the bearer token crosses the network in cleartext on
every request. Only do that on a network you would already trust with the logs.

The key pair is re-read **on every handshake**, so a renewal takes effect without a
restart. This is deliberate: with the usual `ListenAndServeTLS` the pair is read once
at startup, and a process would keep serving the old certificate after renewal —
serving an expired cert for up to 90 days while every renewal reported success.

## Example

```yaml
services:
  gateway:
    image: registry.gitlab.com/sharkops/docker-images/docker-api-gateway:latest
    restart: unless-stopped
    ports:
      - "9375:9375"
    environment:
      GATEWAY_TOKEN: ${GATEWAY_TOKEN:?must be set}
    command:
      - -tls-cert=/etc/letsencrypt/live/example.com/fullchain.pem
      - -tls-key=/etc/letsencrypt/live/example.com/privkey.pem
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/etc/letsencrypt:ro
```

The `:ro` socket mount is defence in depth, not the control — a read-only mount still
permits `POST /containers/{id}/restart`. The allowlist is what stops that.

## Tests

```bash
go test ./...
```

The suite asserts the security boundary rather than the happy path: inspect is
unreachable with a valid token, writes are refused, unknown paths 404, a token that
is a prefix of the real one fails, a path traversal that normalises onto a blocked
path does not smuggle through, `/healthz` does not proxy, and a renewed certificate
is picked up without a restart.
