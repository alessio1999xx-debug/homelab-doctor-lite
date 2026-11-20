# homelab-doctor: one-command health check for a self-hosted box, read-only

Your backup cron may have been writing to `/dev/null` for months. Postgres may be published on `0.0.0.0` with Docker punching a hole through UFW. A certificate may expire next week. A container may be three tags behind. The disk may already be at 93%.

homelab-doctor is one command that looks at those five things on a single Linux host, prints a clear OK / WARN / FAIL report, and exits `1` when something needs attention, so it fits a cron job. It never pulls, restarts, edits firewall rules, renews certificates, or deletes files. One file, Python 3.9+ standard library only, MIT.

Need webhook / email alerts, a deeper Docker firewall audit, or JSON output? That is what the full [PyForge](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) tools are for (one-time payment, yours to keep, no subscription). A "Go further" section later in this README points at the matching product for each check. Or get every tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) ($99, one payment).

- Optional `pip install` (coming soon), or just download the one file. No agent to run, no extra packages.
- Image checks use only `GET` requests to the Docker socket, plus anonymous `HEAD`/tag-list calls to public registries. No image layers are downloaded.
- Port checks read `ss` (or `/proc/net/tcp`) and Docker's published ports. They do not change firewall rules, and they are not a full iptables / `DOCKER-USER` audit.
- Certificate checks only cover hosts you pass with `--cert` or a certs file.
- Cron checks are heuristics (redirects to `/dev/null`, missing `PATH`, non-executable scripts). They cannot see whether a job actually failed last night.
- Flags: `--skip`, `--cert`, `--certs-file`, `--socket`, `--demo`, `--timeout`, `--version`, plus warn/fail thresholds for certs and disk. After `pip install`, use `homelab-doctor` in place of `python3 homelab_doctor.py`.

## Install

`pip install homelab-doctor` is coming soon (PyPI trusted publishing, same flow as the other lite tools). Until the package is published, download the single file (Python 3.9+, standard library only, no extra packages):

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/homelab-doctor-lite/main/homelab_doctor.py
python3 homelab_doctor.py --help
```

## See the output first (offline demo)

```bash
python3 homelab_doctor.py --demo
```

```
homelab-doctor 0.1.0: demo (sample data, no Docker, no network, nothing changed)

Images
  WARN   gitea        gitea/gitea:1.21.0  newer tag 1.21.3
  WARN   redis-cache  redis:7.2-alpine    new digest for :7.2-alpine (b2b2b2b2b2b2 -> d4d4d4d4d4d4); newer tag 7.4-alpine
  OK     traefik      traefik:v2.10.4     digest matches :v2.10.4
  SKIP   my-app       my-app:dev          no registry digest locally (built or loaded locally?)

Ports
  FAIL   docker:postgres  0.0.0.0:5432/tcp    published on all interfaces; UFW is active (Docker often bypasses the host firewall)
  WARN   sshd             0.0.0.0:22/tcp      listening on all interfaces
  OK     docker:gitea     127.0.0.1:3000/tcp  published on loopback only
  OK     caddy            127.0.0.1:8080/tcp  loopback only

Certificates
  OK     vault.lab.example    vault.lab.example:443    expires in 80 days (2027-02-08)
  WARN   blog.lab.example     blog.lab.example:443     expires in 12 days (2026-12-02)
  FAIL   expired.lab.example  expired.lab.example:443  expired 4 days ago (2026-11-16)

Cron
  OK     /etc/crontab        0 6 * * * /usr/bin/apt-get update -qq     no silent-fail signs
  FAIL   /etc/cron.d/backup  0 3 * * * /opt/backup.sh >/dev/null 2>&1  stdout and stderr go to /dev/null, no alert in the command
  WARN   user crontab        0 4 * * * backup.sh                       no PATH in this crontab, command is not an absolute path
  FAIL   /etc/cron.d/sync    0 5 * * * /usr/local/bin/sync.sh          script is not executable: /usr/local/bin/sync.sh

Disk
  FAIL   /       /                93% used (93.0G of 100.0G, fstype ext4) — over the 90% fail threshold
  OK     /boot   /boot            40% used (419.8M of 1.0G, fstype ext4)
  WARN   /var    /var             84% used (42.0G of 50.0G, fstype ext4) — over the 80% warn threshold
  WARN   docker  /var/lib/docker  81% of the filesystem holding /var/lib/docker (8.0G layers, 6.1G images, 1.4G volumes, 800.0M build cache) — over the 80% warn threshold

5 check(s), 12 finding(s): 5 FAIL, 7 WARN, 6 OK, 1 skipped, 0 could not be checked.
Read-only: nothing was changed on this host.
```

## Run it on a real host

```bash
# read-only; needs access to /var/run/docker.sock for the image, Docker-port and Docker-disk checks
# (root, or a user in the docker group). Other checks still run if Docker is missing.
python3 homelab_doctor.py --cert vault.lab.example --cert blog.lab.example:443

python3 homelab_doctor.py --certs-file /etc/homelab-doctor-certs.txt
python3 homelab_doctor.py --skip images,disk
python3 homelab_doctor.py --socket /run/user/1000/docker.sock   # rootless Docker
```

`--certs-file` is a text file: one `host` or `host:port` per line (`#` comments allowed). The default port is 443.

If `DOCKER_HOST` is set to a `unix://` path it is used as the default socket. TCP / SSH Docker hosts are not supported.

## What each check does

| Check | Looks at | Typical WARN / FAIL |
| --- | --- | --- |
| `images` | Running containers, then the public registry (digest + newer version tag, same approach as imagenudge-lite) | WARN if the tag has a new digest or a newer tag exists |
| `ports` | Listening sockets (`ss`, or `/proc/net/tcp`) and Docker publications | FAIL if Docker published a port on all interfaces and UFW/firewalld is active (Docker often bypasses the host firewall). WARN for other `0.0.0.0` / `::` listeners. Loopback is OK |
| `certs` | TLS certificates for `--cert host[:port]` (or `--certs-file`) | WARN within 30 days, FAIL within 7 days or already expired |
| `cron` | `/etc/crontab`, `/etc/cron.d/*`, readable user crontabs | FAIL if stdout and stderr go to `/dev/null` with no alerter in the command, or a script path is not executable. WARN if `PATH` is missing and the command is not an absolute path |
| `disk` | Real filesystems, plus Docker disk usage when the socket is readable | WARN at 80% used, FAIL at 90% (configurable) |

Skip any check with `--skip images` or `--skip images,ports` (repeatable). Image tag lookup can be turned off with `--no-tags`.

Newer image tags keep the same style and suffix as the tag you run: `1.25.1` is compared with `X.Y.Z` tags, `16-alpine` with `N-alpine`, `v2.10.4` with `vX.Y.Z`. Public images only, anonymous access (Docker Hub, and registries that hand out anonymous pull tokens, e.g. public `ghcr.io` and `quay.io` images). No credentials are read or sent.

## Exit codes for cron

| Exit code | Meaning |
| --- | --- |
| `0` | Nothing to flag (or only skipped lines, e.g. certs with no hosts given) |
| `1` | At least one WARN or FAIL |
| `2` | Bad arguments, every check was skipped, or every enabled check failed to run |

```bash
# crontab: check every morning at 07:00, keep the last report
0 7 * * * /usr/bin/python3 /opt/homelab_doctor.py --certs-file /etc/homelab-doctor-certs.txt >> /var/log/homelab-doctor.txt 2>&1
```

Scheduling is up to you (cron, a systemd timer). This tool does not send any alerts itself.

## What it does not do

- It does not pull images, restart containers, edit files, change firewall rules, renew certificates, or delete data.
- It does not send alerts (webhook, ntfy, email) and it has no `--json` flag. Those stay in the full tools.
- It does not discover certificates for you (no ingress crawl, no "find every `.crt` on disk").
- The port check is best-effort. It is not a full iptables / nftables audit of the `DOCKER-USER` chain.
- The cron check is a heuristic. It cannot tell you whether last night's job actually failed.
- It checks one local host. It does not talk to private registries, and it does not replace a monitoring stack.

## Go further

Each check has a matching full PyForge tool if you want alerts or a deeper audit. One-time payment, yours to keep. No subscription. None of these links go to a checkout page.

| Check | Full tool | What it adds |
| --- | --- | --- |
| Images | [ImageNudge](https://py-forge.com/products/imagenudge-container-update-notifier?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) | Compose-file scanning, webhook / ntfy / SMTP alerts, JSON output |
| Ports | [PortExpose](https://py-forge.com/products/portexpose-docker-firewall-auditor?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) | Compose bindings, iptables / `DOCKER-USER` audit, risk classification |
| Certificates | [PulsePing](https://py-forge.com/products/pulseping-cli?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) | Ongoing HTTP/TCP/DNS/TLS monitoring, failure thresholds, alerts |
| Cron | [CronPulse](https://py-forge.com/products/cronpulse-cli?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) | Wraps a job, detects missed runs, alerts, small dashboard |
| Disk | [DiskSweep](https://py-forge.com/products/disksweep?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) | Finds what is using the disk and helps clean it up safely |

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite) ($99, one payment).

## Tests

```bash
python3 test_homelab_doctor.py
```

The tests are offline: canned registry answers, sample `ss` output, fixed certificate dates, temporary certs files. No Docker and no network needed.

## License

MIT (this version). The full PyForge tools linked above are sold separately under their own licenses.
