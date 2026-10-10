# Firewall allowlist for decoys beside a real service

This is an example for the host that owns the public decoy address. It is text to adapt and test,
not a ready-made ruleset. Read the [deployment guide](../DEPLOY_ALONGSIDE_REAL_SERVICE.md) first.

Addresses used here are placeholders from documentation ranges (`203.0.113.0/24`) and a private
VPN subnet (`10.8.0.0/24`). Replace them with your own.

| Address | Role |
|---|---|
| `203.0.113.10` | Public decoy address. Decoys only. Anyone may connect to the decoy ports. |
| `10.8.0.1` | Real management address on the VPN. Real SSH listens here. |
| `10.8.0.0/24` | The VPN subnet. The only source allowed to reach real services. |

The real services listen on `10.8.0.1` or `127.0.0.1`, not on `203.0.113.10`. If the real
service is on another host, put its rules on that host, not here.

## Principles

- **Default drop inbound.** Only the decoy ports on the decoy address and the VPN path to the
  real services are open.
- **Hiding is not the control.** The allowlist limits who can reach the real services. Keep auth,
  MFA and patching on the real services as well.
- **Decoy hosts have no outbound route** to internal networks. Limit outbound traffic on this host
  to what the host needs itself (updates, time, and shipping logs to your own collector).
- **Log drops** at a rate limit, so a scan cannot fill the disk.

## nftables

Save as a file and load it with `sudo nft -f <file>`. Test on a console or out-of-band session
first: a wrong `policy drop` can lock you out of SSH.

```
table inet qlure_edge {
    chain input {
        type filter hook input priority 0; policy drop;

        ct state established,related accept
        iif "lo" accept

        # Decoy ports on the decoy address only. Anyone may connect.
        # 80 and 443: decoy web (or the proxy from the pattern 2 example).
        # 22, 21, 3306, 6379, 2375: fake SSH, FTP, MySQL, Redis and Docker API.
        ip daddr 203.0.113.10 tcp dport { 22, 21, 80, 443, 2375, 3306, 6379 } accept

        # Real SSH on the VPN address, from the VPN subnet only.
        ip saddr 10.8.0.0/24 ip daddr 10.8.0.1 tcp dport 22 accept

        # Real MySQL or Redis on the VPN address, from the VPN subnet only. Uncomment only if
        # you run that service on 10.8.0.1. Never on the public address.
        # ip saddr 10.8.0.0/24 ip daddr 10.8.0.1 tcp dport { 3306, 6379 } accept

        # Log what is dropped: rate limited, then dropped by the policy.
        limit rate 10/second burst 20 packets log prefix "qlure-input-drop: " level info
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
```

Notes:

- `inet` covers IPv4 and IPv6. The rules above match IPv4 only. If the host has IPv6, add
  matching `ip6` rules or drop IPv6 explicitly.
- `203.0.113.10` must be the address the decoys are published on. Check it with `ip -br addr`.
- Real Docker API, MySQL and Redis are not listed. Do not add public rules for them.
- The `forward` chain is dropped so this host does not route traffic between networks. That also
  stops Docker's forwarded traffic. On a Docker host, add accept rules for the decoy containers
  first, test them, and keep the decoy network without a route out, as the guide describes.

## ufw

ufw is simpler and suits a single host. The same placeholders apply.

```
sudo ufw default deny incoming
sudo ufw default deny outgoing      # then allow only what the host needs (see notes)
sudo ufw logging medium

# Decoy ports on the decoy address (anyone may connect).
sudo ufw allow in to 203.0.113.10 port 22 proto tcp
sudo ufw allow in to 203.0.113.10 port 21 proto tcp
sudo ufw allow in to 203.0.113.10 port 80 proto tcp
sudo ufw allow in to 203.0.113.10 port 443 proto tcp
sudo ufw allow in to 203.0.113.10 port 2375 proto tcp
sudo ufw allow in to 203.0.113.10 port 3306 proto tcp
sudo ufw allow in to 203.0.113.10 port 6379 proto tcp

# Real SSH on the VPN address, from the VPN subnet only.
sudo ufw allow from 10.8.0.0/24 to 10.8.0.1 port 22 proto tcp

sudo ufw enable
sudo ufw status verbose
```

Notes:

- `default deny outgoing` on a decoy host blocks everything the host itself sends. Add the
  outbound rules it needs, such as DNS, NTP, package updates and log shipping to your own
  collector. Do not allow general internet access from the decoy host.
- `logging medium` writes drops to the kernel log as `[UFW BLOCK]`. A heavily scanned address
  produces many lines, so watch disk use.
- ufw rules do not stop Docker from publishing ports. Docker inserts its own rules. Publish decoy
  ports only on the decoy address, and test each one from outside.

## Testing from outside

Run these only against addresses you own, from a machine you control, and only before go-live
or when you are checking your own rules.

```
# From a machine outside the VPN: each decoy port should answer, and the real ports should not.
nmap -Pn -p 21,22,80,443,2375,3306,6379 203.0.113.10

# From a machine on the VPN: real SSH should answer on the VPN address.
nmap -Pn -p 22 10.8.0.1

# From a machine with no VPN route: the VPN address should not answer at all.
nmap -Pn -p 22,3306,6379,2375 10.8.0.1
```

Expected results:

| Test | Expected |
|---|---|
| Decoy ports on `203.0.113.10` | open (decoy answers) |
| Any other port on `203.0.113.10` | filtered or closed |
| Real SSH on `10.8.0.1` from outside the VPN | filtered (no answer) |
| Real SSH on `10.8.0.1` from the VPN | open |
| Real database, Redis or Docker API from outside | filtered or closed |
| Decoy host to an internal address or the internet | no connection (test from the decoy host) |
| Dashboard port 9000 from outside | filtered or closed |

After your own test connection, check that the decoy recorded your test machine's address, not
`127.0.0.1` or the proxy's own address. If it shows the proxy's address, check that the stream
server has `proxy_protocol on`.

## Checklist

- [ ] Default drop inbound on the decoy host, and a tested recovery path (console access).
- [ ] Only the decoy ports listed above are open on the decoy address.
- [ ] Real SSH, database, Redis and Docker API are not on any public address.
- [ ] Real SSH allows only the VPN or bastion subnet.
- [ ] Drops are logged and the log is rate limited.
- [ ] The decoy host cannot reach internal networks or the internet (tested from the host).
- [ ] Nmap from outside matches the expected results table.
- [ ] Rules are saved in version control, and a rollback is written down.
