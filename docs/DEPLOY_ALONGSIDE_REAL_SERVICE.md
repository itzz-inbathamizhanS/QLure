# Running QLure beside a real service

This guide is for an operator who already runs a real service (a website, an API, SSH, a
database) and wants QLure's decoys next to it. It covers three layouts, what each one exposes,
a checklist, and the limits. Nothing here has been tested against a production network. Every
example is a starting point to test on your own infrastructure.

The example gateway is [gateway/nginx.real-and-decoy.example.conf](../gateway/nginx.real-and-decoy.example.conf).
The firewall examples are in [docs/examples/firewall-allowlist.md](examples/firewall-allowlist.md).

## 1. What this is and is not

- **A honeypot is bait and a sensor.** The decoys are fake services that answer with fixed
  content and record what a visitor sends. They sit next to the real service. They never
  replace it.
- **Hiding a port is not a security control.** Moving SSH to another port, or leaving a database
  off the public DNS, does not protect it. Scanners find both. The real service must stand on its
  own: authentication, MFA, patching, and a firewall or VPN in front of it. Assume QLure does not
  exist when you secure the real service.
- **QLure is not a WAF**, not an intrusion prevention system, and not a proxy that protects the
  real service. It records; it does not block.
- **Decoys must be isolated.** No real data, no real credentials, and no route to internal
  networks or to the internet. QLure runs on its own host or network segment. It must never run
  at the same trust level as production data.
- **The repository does not do this for you.** `docker-compose.yml` runs the decoys on an
  internal Docker network and publishes them on `127.0.0.1` only. Putting any decoy on a public
  address is a change you make, own, and test.

## 2. Pattern 1: decoys on a separate public address or segment (recommended)

Run the decoys on their own host, VM or network segment, with their own public address. The real
service stays on its own host. The two never share a network path.

```
 Internet
    |
    +--> 203.0.113.10   decoy host (separate VM or host)
    |      gateway -> decoy web 8080, decoy api 8081, decoy ssh 2222,
    |                 decoy banners (21, 3306, 6379), decoy docker api 2375
    |      no route to the real network; no outbound internet
    |
    +--> 198.51.100.20  real service host (separate from the decoys)
           real app on 443; real SSH and databases on a VPN address only
```

**Name the decoys carefully.** A decoy hostname (for example `old-portal.example.com`) must not
match any real name in your DNS, and must not be a name a real system uses. Do not give decoy
hosts the names of real servers (for example `db01`): people reading logs will mix them up, and
an attacker learns nothing from a name that is also used for something real. Keep the fake
company name in `runtime/content.json` (the default is "Veltrix Logistics") fictional, not your
own.

**What is exposed:** only the decoy services, on the decoy address. Nothing from the real host.
If you publish a decoy on 443, give it a certificate for its own hostname.

## 3. Pattern 2: one reverse proxy, real and decoy by hostname and path

One public proxy takes the traffic. The real hostname and its normal paths go to the real
application. Everything else goes to the decoy web.

```
 visitor --> proxy (public address, 443 and 80)
   Host app.example.com, normal path   --> real app (real-app.internal:8443)
   unknown Host, or a bare IP address  --> decoy web (decoy-web:8080)
   scanner-only path (/.env, /.git/...) --> decoy web, on the DEFAULT server only
```

The example in `gateway/nginx.real-and-decoy.example.conf` shows this layout. Rules that must hold:

- **The real application must not use the decoy paths.** The decoy web has routes at `/.env`,
  `/.git/HEAD`, `/.git/config`, `/backup/`, `/phpmyadmin`, `/pma`, `/server-status`, `/uploads`
  and everything under `/api`. If your real app serves any of these on the hostname the decoy
  also answers, the two collide. The example also sends `/wp-login.php` and `/wp-admin/` to the
  decoy. The decoy has no route there, so it logs the request and answers 404.
- **Decoy routes exist only in the default servers**, never in the server for the real
  hostname. A real visitor who requests `/.env` on the real hostname gets the real app's answer,
  and QLure does not see it. That is intended.
- **Health checks and monitors must use the hostname**, not the bare IP address. A check made by
  IP lands on the decoy and looks like an attacker.
- **The decoy web trusts `X-Forwarded-For` only from the proxy.** The decoy's uvicorn reads that
  header only from the address listed in `--forwarded-allow-ips`. Set it to your proxy's address.
  The compose stack uses `172.30.0.2` for its gateway. Keep the proxy's `X-Forwarded-For
  $remote_addr` line (it overwrites the header, so a visitor cannot choose it).
- **TLS ends at the proxy.** The decoy web speaks plain HTTP behind it. The real app is reached
  over HTTPS and the example verifies its certificate with `proxy_ssl_verify on`.

## 4. Pattern 3: raw TCP ports (SSH, FTP, MySQL, Redis, Docker API)

Use this only when the services must be on their own ports. It is the weakest layout, because
the decoys and the real services are close together.

- **Real SSH, MySQL, Redis and the Docker API are never public.** Reach them only from a VPN, a
  bastion, or an allowlist subnet, enforced by the firewall. See
  [docs/examples/firewall-allowlist.md](examples/firewall-allowlist.md). Never publish the real
  Docker API, Redis or MySQL on a public address, with or without a password.
- **Decoys sit on the default ports** (22, 21, 3306, 6379, 2375) on the decoy address. In this
  repository the decoys listen on 2222 (SSH), 2121 (FTP), 3306, 6379 and 2375 inside their
  network. The compose file publishes 2222 and 2121 on `127.0.0.1`. To present them on 22 and 21,
  map the public port to the decoy's port (the example's stream block does this).
- **Ports below 1024 need privilege.** The compose gateway runs as user 101, so it cannot bind 21
  or 22 as configured. A host-level port mapping, or nginx started as root on the decoy host,
  does this. Test which one you use.
- **Moving the real SSH to a non-default port is a second layer only.** It adds noise to scans
  and nothing more. The firewall is the control.
- **Do not run both layouts on one host with the real data.** If the decoy and the real service
  share a host, a decoy problem becomes a real-data problem. Put the decoys on their own host or
  VM.

## 5. What an attacker sees, what a customer sees, what you see

"Attacker" means a visitor who reaches the decoy. "Customer" means a legitimate user of the real
service. "You" means the operator, through QLure's event types (see
[architecture 3](architecture/03-decoys.md)).

| Service | An attacker sees | A customer sees | You see (event kinds) |
|---|---|---|---|
| Web | On the decoy hostname or default server: a login page, a fake `/.env`, a fake `/backup/config.bak`, fake `/.git` files, a phpMyAdmin login. Unknown paths get a 404. | The real app at the real hostname, unchanged. | `http_request`, `login_attempt`, `file_read`, `honeytoken_use` (decoy traffic only) |
| API | A 401 JSON reply on `/api*`. A planted key is accepted on `/api/v1/` routes. | The real API at its own hostname. | `http_request`, `api_call`, `login_attempt`, `honeytoken_use` |
| SSH | A login prompt on port 22 of the decoy address. Only the planted password works, then a fake shell. | Real SSH only from the VPN or bastion. Nothing on the public address. | `connect`, `login_attempt`, `login_success`, `command`, `honeytoken_use` |
| FTP | A greeting, then USER and PASS. Every password gets "530 Login incorrect". | Nothing, unless you run a real FTP service (then it follows the same rule as SSH). | `connect`, `banner`, `login_attempt`, `honeytoken_use` |
| MySQL | An 8.0 greeting, then "access denied" for every login. | Real MySQL only from a private or VPN address. | `connect`, `banner`, `login_attempt` |
| Redis | No greeting. Commands get NOAUTH until AUTH. The planted password unlocks fixed replies. | Real Redis only from a private address. | `connect`, `banner`, `login_attempt`, `honeytoken_use`, `command` |
| Docker API | Fixed Docker 24.0.7 JSON. Create and exec return a fake id. Nothing runs. | Nothing. The real Docker API is never public. | `http_request` (body capped at 2 KB) |
| Dashboard | Nothing. It is not on any public address. | Nothing. | You, on localhost or the VPN only |

## 6. Checklist

Work through this before go-live, and again after every change.

1. **Network isolation.** The decoy host or segment has no route to internal networks, and its
   outbound traffic is denied at the host firewall except for what the host itself needs. Test
   it from the decoy host: no connection to an internal address or to the internet succeeds.
   Compose uses `internal: true` for `decoynet`, and runs `qlure watch-egress` beside each
   decoy to record any connection a decoy opens.
2. **No real secrets, data or hostnames** in the decoy configuration, the content file or the
   fake file tree. Every planted value in `decoys/honeytokens.yaml` is fake and contains the word
   "decoy".
3. **`QLURE_PROXY_PROTOCOL=required`** behind the gateway. This is the default; the compose
   file never sets it. `optional` exists only for local runs on loopback. The SSH and banner
   decoys refuse to start with `optional` on a non-loopback bind address. In `optional` mode any
   client can forge a PROXY line and claim any source address.
4. **`QLURE_BIND_HOST`** set to the private address the gateway uses to reach the decoy. The
   default is `0.0.0.0`, which is right only inside an isolated Docker network.
5. **Keep the `X-Forwarded-For $remote_addr` overwrite** in the proxy, and list only the proxy's
   address in `--forwarded-allow-ips` on the uvicorn decoys.
6. **Dashboard on localhost or the VPN only.** Publish it on `127.0.0.1:9000` (compose does this)
   or on a VPN address. Set `QLURE_DASHBOARD_PASSWORD` and `QLURE_DASHBOARD_SECRET`. Set
   `QLURE_COOKIE_SECURE=1` only when the dashboard is served over HTTPS. Leave
   `QLURE_METRICS_PUBLIC` unset. For a shared read-only view, use the judge-locked demo in
   [DEPLOY_RENDER.md](DEPLOY_RENDER.md), which holds no live decoys.
7. **Alerts with `qlure alert`.** Off by default. Give the webhook URL through the
   `QLURE_ALERT_WEBHOOK` variable or `--url`. Treat the URL as a secret: keep it out of the
   repository, shell history and screenshots. QLure shows it masked. Test with `--dry-run` first.
   See [ALERTS.md](ALERTS.md).
8. **Evidence.** Run `qlure verify` on a schedule. Keep the logs and the database out of git
   (they are already in `.gitignore`). Retention is manual: nothing runs `qlure prune` for you.
   Preview with `qlure prune --older-than 30d --dry-run`, then run it with `--yes`. See
   [RETENTION.md](RETENTION.md).
9. **Honeytokens.** Only the values that a decoy accepts give a signal when they are used against
   a decoy: `ht-aws-001` (API), `ht-db-001` (web login and FTP), `ht-ssh-001` (SSH, web login and
   FTP), `ht-api-001` (API) and `ht-redis-001` (Redis). The planted-only values `ht-git-001`,
   `ht-sshkey-001` and `ht-canary-001` raise no alert when used. Plant the accepted values in
   places a legitimate user never reads, such as an unused backup in your own repository. A
   planted value used against the real service fails there, and QLure does not see that. The
   values are fixed and published in this repository, so treat them as known bait, never as
   secrets, and never use them for anything real.
10. **Test from outside before go-live.** Scan your own public address from a machine you
    control. Every decoy port answers, and the real services do not answer from outside the VPN.
    The table and commands are in [firewall-allowlist.md](examples/firewall-allowlist.md).
11. **Rollback plan.** Write down the previous proxy configuration and keep a copy. The rollback
    is: restore that configuration, check the real site loads, and stop the decoy stack on its
    host with `docker compose down`. Lower the DNS TTL for the names you change before the change.

## 7. Legal, privacy and operations

- **Visitor addresses and typed text are personal data** in many places. QLure logs both
  (the decoys record source addresses, passwords typed into the fake login forms, and commands).
  Decide the legal basis, the retention period and who can read the logs before go-live, and
  check your local law. Keep the retention period short and run `qlure prune` on it.
- **Tell the network and security teams before go-live.** Add the decoy hosts to your inventory.
  Agree who answers an alert, and how fast. Expect many scanner hits from the first day.
- **Monitor that the decoy network cannot be used as a pivot.** A decoy that can reach an
  internal address is a path into your network. Check the egress watcher output and the host
  firewall logs regularly, and alert on any connection a decoy opens.
- **Real customers may hit the decoy.** A user with a stale bookmark, a wrong hostname or a bare
  IP check lands on the decoy. Do not treat that visitor as an attacker without review.
- **Review changes.** The proxy, firewall and decoy configuration are part of your change
  management. Review them like any other change to production edge infrastructure.
- **Defensive use only.** Use what QLure records to defend your own systems. Do not use it to
  act against the people who connected.

## 8. Limits

- **Not a WAF.** QLure does not block, filter or rate limit traffic to the real service.
- **TLS certificates.** Each decoy hostname needs a certificate that matches it. A default
  server with a certificate for the wrong name shows a warning to every visitor.
- **CDN and proxy source addresses.** Behind a CDN or a load balancer, `$remote_addr` is that
  proxy's address. The overwrite then records the proxy, not the visitor. Using the CDN's
  forwarded-address header is a separate setup, and this guide does not cover it. Trust a
  forwarded header only from addresses you control.
- **Real users on scanner paths.** On the real hostname, real visitors who request a decoy path
  get the real app's answer. QLure does not record them. That is by design.
- **Shallow decoys.** The services answer with fixed text and a few replies. A determined visitor
  will notice. A decoy reply is not evidence about the real service.
- **No network test here.** This repository does not test a live setup against any production
  network. The example nginx configuration is checked for its structure by the test suite, and
  `nginx -t` runs only where nginx is installed. Your network needs its own tests.
- **Hiding is not protection.** Nothing in this guide makes the real service hidden. The real
  service is protected by its own controls and the firewall.
