#!/usr/bin/env python3
"""homelab-doctor: read-only health check for a self-hosted / homelab box.

One command that looks at five common ways a homelab goes quiet or gets
exposed: running containers with a newer image, ports listening on all
interfaces (including Docker publications that often bypass the host
firewall), TLS certificates about to expire, cron jobs that look like they
fail silently, and disk (plus Docker disk) filling up.

It prints a plain-text report (OK / WARN / FAIL) and exits 1 when something
needs attention, so it fits a cron job. It never changes the host: no
pulls, no restarts, no firewall edits, no file changes.

Registry access is anonymous only (public images). Python 3.9+ standard
library only. MIT license.

Exit codes: 0 = nothing to flag, 1 = at least one WARN or FAIL, 2 = error
(bad arguments, or every enabled check failed to run).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "0.1.0"

CHECKS = ("images", "ports", "certs", "cron", "disk")
OK, WARN, FAIL, SKIP, ERROR = "OK", "WARN", "FAIL", "SKIP", "ERROR"
STATUSES = (FAIL, WARN, OK, SKIP, ERROR)

DEFAULT_SOCKET = "/var/run/docker.sock"
USER_AGENT = "homelab-doctor/" + __version__
UTM = "utm_source=github&utm_medium=readme&utm_campaign=homelab-doctor-lite"
SITE = "https://py-forge.com"
PASS_URL = SITE + "/pass?" + UTM
IMAGE_URL = SITE + "/products/imagenudge-container-update-notifier?" + UTM
PORT_URL = SITE + "/products/portexpose-docker-firewall-auditor?" + UTM
CERT_URL = SITE + "/products/pulseping-cli?" + UTM
CRON_URL = SITE + "/products/cronpulse-cli?" + UTM
DISK_URL = SITE + "/products/disksweep?" + UTM

DEFAULT_CERT_WARN_DAYS = 30
DEFAULT_CERT_FAIL_DAYS = 7
DEFAULT_DISK_WARN = 80
DEFAULT_DISK_FAIL = 90

MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)

DISK_FS = frozenset(
    {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "zfs_member", "f2fs",
        "vfat", "exfat", "ntfs", "ntfs3", "nfs", "nfs4", "cifs", "smb3",
        "fuse.sshfs", "fuseblk", "jfs", "reiserfs", "udf",
    }
)

CRON_ALERTERS = (
    "cronpulse", "cronpulse-lite", "cronpulse_lite", "healthchecks", "ntfy",
    "logger", "systemd-cat", "mail", "mailx", "sendmail", "curl", "wget",
)

DEMO_NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


class DockerError(Exception):
    """The local Docker socket could not be read."""


# --- Image references and tags (same approach as imagenudge-lite) ---


class ImageRef:
    """A Docker image reference split into registry, repository, tag, digest."""

    def __init__(self, raw: str) -> None:
        self.raw = raw.strip()
        self.registry = "docker.io"
        self.repository = ""
        self.tag = "latest"
        self.digest = ""
        self.tag_given = False
        ref = self.raw
        if "@" in ref:
            ref, self.digest = ref.split("@", 1)
        first = ref.split("/", 1)
        if len(first) == 2 and ("." in first[0] or ":" in first[0] or first[0] == "localhost"):
            self.registry = first[0]
            ref = first[1]
        last = ref.rsplit("/", 1)[-1]
        if ":" in last:
            ref, self.tag = ref.rsplit(":", 1)
            self.tag_given = True
        self.repository = ref
        if self.registry in ("docker.io", "index.docker.io", "registry-1.docker.io"):
            self.registry = "docker.io"
            if "/" not in self.repository:
                self.repository = "library/" + self.repository

    @property
    def api_host(self) -> str:
        return "registry-1.docker.io" if self.registry == "docker.io" else self.registry

    @property
    def key(self) -> str:
        return "%s/%s:%s" % (self.registry, self.repository, self.tag)


def parse_semver(tag: str) -> Optional[Tuple[int, int, int, str]]:
    """'v1.2.3-alpine' -> (1, 2, 3, 'alpine'); None if the tag is not version-like."""
    m = re.match(r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$", tag)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), m.group(4) or "")


def find_newer_tag(current: str, tags: List[str]) -> Optional[str]:
    """Highest tag newer than `current` with the same suffix and the same style."""
    cur = parse_semver(current)
    if not cur:
        return None
    best, best_core = None, cur[:3]
    dots, vpref = current.count("."), current[:1] in "vV"
    for t in tags:
        p = parse_semver(t)
        if not p or p[3] != cur[3] or t.count(".") != dots or (t[:1] in "vV") != vpref:
            continue
        if p[:3] > best_core:
            best, best_core = t, p[:3]
    return best


def pick_local_digest(repo_digests: List[str], ref: ImageRef) -> Optional[str]:
    for entry in repo_digests or []:
        if "@" not in entry:
            continue
        name, digest = entry.split("@", 1)
        other = ImageRef(name)
        if other.registry == ref.registry and other.repository == ref.repository:
            return digest
    return None


def short_digest(digest: str) -> str:
    return digest.split(":", 1)[-1][:12] if digest else "?"


def _row(check: str, status: str, name: str, target: str, detail: str) -> Dict[str, str]:
    return {"check": check, "status": status, "name": name, "target": target, "detail": detail}



# --- Local Docker socket (read-only GET requests) ---


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTP over a local UNIX domain socket."""

    def __init__(self, socket_path: str, timeout: float = 5) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class DockerClient:
    """Only GET requests against the local Docker API."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET, timeout: float = 5) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def get_json(self, path: str) -> Any:
        conn = UnixSocketHTTPConnection(self.socket_path, timeout=self.timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": USER_AGENT})
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                raise DockerError("Docker API %s returned HTTP %d" % (path, resp.status))
            return json.loads(body.decode("utf-8"))
        except DockerError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise DockerError("cannot read Docker socket %s: %s" % (self.socket_path, exc))
        finally:
            conn.close()

    def list_containers(self) -> List[Dict[str, Any]]:
        data = self.get_json("/containers/json")
        if not isinstance(data, list):
            raise DockerError("unexpected /containers/json response")
        return data

    def inspect_image(self, image_id: str) -> Optional[Dict[str, Any]]:
        try:
            data = self.get_json("/images/%s/json" % urllib.parse.quote(image_id, safe=":"))
        except DockerError:
            return None
        return data if isinstance(data, dict) else None

    def info(self) -> Dict[str, Any]:
        data = self.get_json("/info")
        return data if isinstance(data, dict) else {}

    def system_df(self) -> Dict[str, Any]:
        data = self.get_json("/system/df")
        return data if isinstance(data, dict) else {}


def default_socket() -> str:
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return host[len("unix://"):]
    return DEFAULT_SOCKET


def parse_bearer_challenge(header: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not header or not header.lower().startswith("bearer "):
        return out
    for m in re.finditer(r'([A-Za-z_]+)="([^"]*)"', header[7:]):
        out[m.group(1).lower()] = m.group(2)
    return out


class RegistryClient:
    """HEAD manifests and list tags, with an anonymous pull credential when asked."""

    def __init__(self, timeout: float = 10, urlopen: Optional[Callable[..., Any]] = None) -> None:
        self.timeout = timeout
        self.urlopen = urlopen or urllib.request.urlopen
        self.cached: Dict[str, str] = {}
        self.ctx = ssl.create_default_context()

    def _pull_access(self, challenge: Dict[str, str], repository: str) -> Optional[str]:
        realm = challenge.get("realm", "")
        if not realm.startswith("https://"):
            return None
        params = {"scope": challenge.get("scope") or "repository:%s:pull" % repository}
        if challenge.get("service"):
            params["service"] = challenge["service"]
        url = realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(params)
        if url in self.cached:
            return self.cached[url]
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with self.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError):
            return None
        value = data.get("token") or data.get("access_token") if isinstance(data, dict) else None
        if value:
            self.cached[url] = value
        return value

    def _request(self, url: str, method: str, accept: str, repository: str) -> Tuple[Any, bytes]:
        headers = {"User-Agent": USER_AGENT}
        if accept:
            headers["Accept"] = accept
        for attempt in (1, 2):
            req = urllib.request.Request(url, headers=headers, method=method)
            try:
                with self.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    return resp.headers, (resp.read() if method == "GET" else b"")
            except urllib.error.HTTPError as err:
                if err.code == 401 and attempt == 1:
                    access = self._pull_access(
                        parse_bearer_challenge(err.headers.get("Www-Authenticate", "")),
                        repository,
                    )
                    if access:
                        headers["Authorization"] = "Bearer " + access
                        continue
                    raise RuntimeError(
                        "registry asked for credentials: private or missing image (public images only)"
                    )
                if err.code == 401:
                    raise RuntimeError(
                        "registry asked for credentials: private or missing image (public images only)"
                    )
                if err.code == 404:
                    raise RuntimeError("tag or repository not found on the registry")
                if err.code == 429:
                    raise RuntimeError("registry rate limit hit (HTTP 429), try later")
                raise RuntimeError("registry HTTP %d" % err.code)
            except (urllib.error.URLError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                raise RuntimeError("registry unreachable: %s" % reason)
        raise RuntimeError("registry request failed")

    def remote_digest(self, ref: ImageRef) -> str:
        url = "https://%s/v2/%s/manifests/%s" % (ref.api_host, ref.repository, ref.tag)
        hdrs, _ = self._request(url, "HEAD", MANIFEST_ACCEPT, ref.repository)
        digest = hdrs.get("Docker-Content-Digest") if hdrs is not None else None
        if not digest:
            raise RuntimeError("registry did not return a digest")
        return digest

    def list_tags(self, ref: ImageRef, max_pages: int = 3) -> List[str]:
        host = ref.api_host
        url: Optional[str] = "https://%s/v2/%s/tags/list?n=1000" % (host, ref.repository)
        tags: List[str] = []
        for _ in range(max_pages):
            if not url:
                break
            hdrs, body = self._request(url, "GET", "", ref.repository)
            try:
                tags.extend(json.loads((body or b"{}").decode("utf-8")).get("tags") or [])
            except (ValueError, AttributeError):
                raise RuntimeError("invalid tag list response")
            url = None
            link = (hdrs.get("Link", "") if hdrs is not None else "") or ""
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if m:
                nxt = m.group(1)
                if nxt.startswith("/"):
                    nxt = "https://%s%s" % (host, nxt)
                if nxt.startswith("https://%s/" % host):
                    url = nxt
        return tags


def running_containers(docker: DockerClient) -> List[Dict[str, Any]]:
    """[{name, image, local_digest}] for every running container."""
    out = []
    for c in docker.list_containers():
        names = c.get("Names") or ["/unknown"]
        name = (names[0] or "/unknown").lstrip("/")
        image = c.get("Image", "") or ""
        local_digest = None
        image_id = c.get("ImageID", "")
        if image_id and image and not image.startswith("sha256:"):
            info = docker.inspect_image(image_id)
            if info:
                local_digest = pick_local_digest(info.get("RepoDigests") or [], ImageRef(image))
        out.append({"name": name, "image": image, "local_digest": local_digest})
    out.sort(key=lambda x: x["name"])
    return out


def check_images(containers: List[Dict[str, Any]], registry: Any, tag_check: bool = True) -> List[Dict[str, Any]]:
    """One result per container. A newer image is WARN (not FAIL): review, then update when you choose."""
    cache: Dict[str, Tuple[str, str]] = {}
    results: List[Dict[str, Any]] = []
    for c in containers:
        image = c.get("image") or ""
        name = c.get("name") or "?"
        if not image or image.startswith("sha256:"):
            results.append(_row("images", SKIP, name, image, "started from an image ID, no tag to check"))
            continue
        ref = ImageRef(image)
        if ref.digest and not ref.tag_given:
            results.append(_row("images", SKIP, name, image, "pinned by digest, no tag to check"))
            continue
        local = c.get("local_digest") or (ref.digest or None)
        if not local:
            results.append(_row("images", SKIP, name, image, "no registry digest locally (built or loaded locally?)"))
            continue
        ck = ref.key + "|" + local
        if ck not in cache:
            cache[ck] = _check_one_image(ref, local, registry, tag_check)
        status, detail = cache[ck]
        results.append(_row("images", status, name, image, detail))
    return results


def _check_one_image(ref: ImageRef, local: str, registry: Any, tag_check: bool) -> Tuple[str, str]:
    try:
        remote = registry.remote_digest(ref)
    except RuntimeError as exc:
        return ERROR, str(exc)
    reasons = []
    if remote != local:
        reasons.append("new digest for :%s (%s -> %s)" % (ref.tag, short_digest(local), short_digest(remote)))
    if tag_check and parse_semver(ref.tag):
        try:
            newer = find_newer_tag(ref.tag, registry.list_tags(ref))
        except RuntimeError:
            newer = None
        if newer:
            reasons.append("newer tag %s" % newer)
    if reasons:
        return WARN, "; ".join(reasons)
    return OK, "digest matches :%s" % ref.tag



# --- Ports: ss /proc + Docker publications + a best-effort firewall hint ---


def parse_ss_listen(text: str) -> List[Dict[str, str]]:
    """Parse `ss -lntuh` or `ss -lnt` into [{proto, ip, port, process}]."""
    out: List[Dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("state") or line.lower().startswith("netid"):
            continue
        parts = line.split()
        proto_m = re.match(r"^(tcp|udp)\b", line, re.I)
        if proto_m:
            proto = proto_m.group(1).lower()
            # Netid State Recv-Q Send-Q Local Address:Port
            local_idx = 4
        elif re.match(r"^(LISTEN|UNCONN)\b", line, re.I):
            proto = "udp" if parts[0].upper() == "UNCONN" else "tcp"
            # State Recv-Q Send-Q Local Address:Port
            local_idx = 3
        else:
            continue
        if len(parts) <= local_idx:
            continue
        parsed = split_hostport(parts[local_idx])
        if not parsed:
            continue
        ip, port = parsed
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        out.append({"proto": proto, "ip": ip, "port": port, "process": proc})
    return out


def split_hostport(value: str) -> Optional[Tuple[str, str]]:
    """Split '0.0.0.0:5432', '[::]:80', '*:22', ':::80' into (ip, port)."""
    value = value.strip()
    if value.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", value)
        if not m:
            return None
        return m.group(1), m.group(2)
    if value.count(":") == 1:
        ip, port = value.split(":")
        return (ip or "0.0.0.0"), port
    m = re.match(r"^(.*):(\d+)$", value)
    if not m:
        return None
    return m.group(1), m.group(2)


def is_wildcard_ip(ip: str) -> bool:
    ip = (ip or "").strip().strip("[]").lower()
    return ip in ("0.0.0.0", "::", "*", "", "::0")


def is_loopback_ip(ip: str) -> bool:
    ip = (ip or "").strip().strip("[]").lower()
    return ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127.")


def _hex_ipv4(h: str) -> str:
    raw = bytes.fromhex(h)
    raw = bytes(reversed(raw))  # /proc/net/tcp is little-endian on Linux
    return "%d.%d.%d.%d" % tuple(raw)


def _hex_ipv6(h: str) -> str:
    parts = [h[i:i + 8] for i in range(0, 32, 8)]
    b = b"".join(bytes(reversed(bytes.fromhex(p))) for p in parts)
    hextets = ["%x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2)]
    return ":".join(hextets)


def parse_proc_net(text: str, ipv6: bool = False) -> List[Dict[str, str]]:
    """Parse /proc/net/tcp or /proc/net/tcp6 listening sockets (state 0A)."""
    out: List[Dict[str, str]] = []
    for i, raw in enumerate(text.splitlines()):
        if i == 0:
            continue
        parts = raw.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        local = parts[1]
        if ":" not in local:
            continue
        addr_h, port_h = local.split(":")
        try:
            port = str(int(port_h, 16))
            ip = _hex_ipv6(addr_h) if ipv6 else _hex_ipv4(addr_h)
        except ValueError:
            continue
        out.append({"proto": "tcp", "ip": ip, "port": port, "process": ""})
    return out


def read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def run_cmd(argv: List[str], timeout: float = 5) -> Optional[str]:
    """Run a read-only command. Returns stdout or None on failure."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return proc.stdout if proc.stdout else None
    return proc.stdout


def collect_listen_ports(
    ss_output: Optional[str] = None, proc_files: Optional[Dict[str, str]] = None
) -> List[Dict[str, str]]:
    """Listening sockets from ss, or /proc/net/tcp{,6} if ss is missing."""
    if ss_output is None:
        ss_output = run_cmd(["ss", "-lntuh"])
    if ss_output:
        rows = parse_ss_listen(ss_output)
        if rows:
            return rows
    files = proc_files if proc_files is not None else {}
    rows = []
    mapping = (
        ("/proc/net/tcp", False, "tcp"),
        ("/proc/net/tcp6", True, "tcp"),
        ("/proc/net/udp", False, "udp"),
        ("/proc/net/udp6", True, "udp"),
    )
    for path, ipv6, proto in mapping:
        text = files.get(path, read_text(path) if proc_files is None else None)
        if not text:
            continue
        for row in parse_proc_net(text, ipv6=ipv6):
            row["proto"] = proto
            rows.append(row)
    return rows


def docker_published_ports(containers: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Published host ports from GET /containers/json (the Ports field)."""
    out: List[Dict[str, str]] = []
    for c in containers or []:
        names = c.get("Names") or ["/unknown"]
        name = (names[0] or "/unknown").lstrip("/")
        for p in c.get("Ports") or []:
            public = p.get("PublicPort")
            if not public:
                continue
            ip = p.get("IP") or "0.0.0.0"
            proto = (p.get("Type") or "tcp").lower()
            out.append(
                {
                    "proto": proto,
                    "ip": ip,
                    "port": str(public),
                    "process": "docker:" + name,
                    "container": name,
                    "private": str(p.get("PrivatePort") or ""),
                }
            )
    out.sort(key=lambda r: (int(r["port"] or 0), r["ip"], r.get("container") or ""))
    return out


def detect_firewall(ufw_status: Optional[str] = None, firewalld_state: Optional[str] = None) -> Dict[str, str]:
    """Best-effort: is UFW or firewalld active? Does not audit iptables rules."""
    if ufw_status is None:
        ufw_status = run_cmd(["ufw", "status"])
    if ufw_status:
        first = ufw_status.strip().splitlines()[0].lower() if ufw_status.strip() else ""
        if "inactive" in first:
            return {"name": "ufw", "state": "inactive", "label": "UFW is inactive"}
        if "active" in first:
            return {"name": "ufw", "state": "active", "label": "UFW is active"}
    if firewalld_state is None:
        firewalld_state = run_cmd(["firewall-cmd", "--state"])
    if firewalld_state:
        state = firewalld_state.strip().lower()
        if state == "running":
            return {"name": "firewalld", "state": "active", "label": "firewalld is running"}
        if state:
            return {"name": "firewalld", "state": "inactive", "label": "firewalld is not running"}
    return {"name": "", "state": "unknown", "label": "no host firewall detected"}


def check_ports(
    listeners: List[Dict[str, str]],
    published: List[Dict[str, str]],
    firewall: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Flag 0.0.0.0 / :: listeners and Docker publications. Loopback is OK (shown)."""
    fw = firewall or detect_firewall()
    results: List[Dict[str, Any]] = []
    published_keys = set()
    for p in published:
        published_keys.add((p.get("proto") or "tcp", p["ip"], p["port"]))
        published_keys.add((p.get("proto") or "tcp", "0.0.0.0", p["port"]))
        published_keys.add((p.get("proto") or "tcp", "::", p["port"]))
        target = "%s:%s/%s" % (p["ip"] or "0.0.0.0", p["port"], p.get("proto") or "tcp")
        name = p.get("process") or ("docker:" + (p.get("container") or "?"))
        if is_loopback_ip(p["ip"]):
            results.append(_row("ports", OK, name, target, "published on loopback only"))
            continue
        if is_wildcard_ip(p["ip"]):
            if fw.get("state") == "active":
                results.append(
                    _row(
                        "ports",
                        FAIL,
                        name,
                        target,
                        "published on all interfaces; %s (Docker often bypasses the host firewall)"
                        % fw["label"],
                    )
                )
            elif fw.get("state") == "inactive":
                results.append(
                    _row(
                        "ports",
                        WARN,
                        name,
                        target,
                        "published on all interfaces; %s" % fw["label"],
                    )
                )
            else:
                results.append(
                    _row(
                        "ports",
                        WARN,
                        name,
                        target,
                        "published on all interfaces; no host firewall detected (this is not a full iptables audit)",
                    )
                )
        else:
            results.append(_row("ports", OK, name, target, "published on a specific address"))

    seen_listen = set()
    for item in listeners:
        proto = item.get("proto") or "tcp"
        key = (proto, item.get("ip") or "", item.get("port") or "")
        wild_keys = {
            (proto, item.get("ip") or "", item.get("port") or ""),
            (proto, "0.0.0.0", item.get("port") or ""),
            (proto, "::", item.get("port") or ""),
        }
        if wild_keys & published_keys:
            continue
        if key in seen_listen:
            continue
        seen_listen.add(key)
        process = item.get("process") or "host"
        if process in ("docker-proxy", "docker"):
            process = "docker-proxy"
        target = "%s:%s/%s" % (item.get("ip") or "?", item.get("port") or "?", proto)
        ip = item.get("ip") or ""
        if is_loopback_ip(ip):
            results.append(_row("ports", OK, process, target, "loopback only"))
        elif is_wildcard_ip(ip):
            results.append(_row("ports", WARN, process, target, "listening on all interfaces"))
        else:
            results.append(_row("ports", OK, process, target, "listening on a specific address"))

    if not results:
        results.append(_row("ports", OK, "ports", "-", "no listening TCP/UDP sockets found"))

    def sort_key(r: Dict[str, Any]) -> Tuple[int, str, str]:
        order = {FAIL: 0, WARN: 1, ERROR: 2, OK: 3, SKIP: 4}
        return (order.get(r["status"], 9), r.get("target") or "", r.get("name") or "")

    results.sort(key=sort_key)
    return results



# --- TLS certificates ---


def parse_hostport(value: str, default_port: int = 443) -> Tuple[str, int]:
    """Parse 'host:port', 'host', or '[ipv6]:port'."""
    value = value.strip()
    if not value:
        raise ValueError("empty host")
    if value.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", value)
        if not m:
            raise ValueError("invalid host:port %r" % value)
        return m.group(1), int(m.group(2) or default_port)
    if value.count(":") == 1:
        host, port_s = value.split(":")
        if not host:
            raise ValueError("invalid host:port %r" % value)
        return host, int(port_s)
    if value.count(":") > 1:
        return value, default_port
    return value, default_port


def load_cert_targets(
    values: Sequence[str], certs_file: Optional[str] = None, file_text: Optional[str] = None
) -> List[Tuple[str, int]]:
    raw: List[str] = list(values or [])
    if certs_file or file_text is not None:
        text = file_text if file_text is not None else read_text(certs_file or "")
        if text is None:
            raise OSError("cannot read certs file %s" % certs_file)
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("cert "):
                line = line[5:].strip()
            raw.append(line)
    seen = set()
    out: List[Tuple[str, int]] = []
    for item in raw:
        host, port = parse_hostport(item)
        key = (host, port)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def cert_expiry_utc(cert: Dict[str, Any]) -> datetime:
    not_after = cert.get("notAfter")
    if not not_after:
        raise RuntimeError("certificate has no notAfter")
    seconds = ssl.cert_time_to_seconds(not_after)
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def fetch_peer_cert(host: str, port: int, timeout: float = 10) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    # Still return the certificate when verification would fail (expired, name mismatch).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    if not cert:
        raise RuntimeError("server presented no certificate")
    return cert


def classify_days_left(days_left: int, warn_days: int, fail_days: int) -> Tuple[str, str]:
    if days_left < 0:
        ago = abs(days_left)
        unit = "day" if ago == 1 else "days"
        return FAIL, "expired %d %s ago" % (ago, unit)
    if days_left <= fail_days:
        return FAIL, "expires in %d %s" % (days_left, "day" if days_left == 1 else "days")
    if days_left <= warn_days:
        return WARN, "expires in %d days" % days_left
    return OK, "expires in %d days" % days_left


def check_certs(
    targets: List[Tuple[str, int]],
    now: Optional[datetime] = None,
    warn_days: int = DEFAULT_CERT_WARN_DAYS,
    fail_days: int = DEFAULT_CERT_FAIL_DAYS,
    fetch: Optional[Callable[[str, int], Dict[str, Any]]] = None,
    timeout: float = 10,
) -> List[Dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    fetch = fetch or (lambda h, p: fetch_peer_cert(h, p, timeout=timeout))
    if not targets:
        return [
            _row("certs", SKIP, "certs", "-", "no hosts given; pass --cert host:port or --certs-file")
        ]
    results = []
    for host, port in targets:
        target = "%s:%d" % (host, port)
        try:
            cert = fetch(host, port)
            expiry = cert_expiry_utc(cert)
        except (OSError, socket.error, ssl.SSLError, RuntimeError, ValueError) as exc:
            results.append(_row("certs", ERROR, host, target, "could not read certificate: %s" % exc))
            continue
        days_left = int((expiry - now).total_seconds() // 86400)
        status, detail = classify_days_left(days_left, warn_days, fail_days)
        detail = "%s (%s)" % (detail, expiry.date().isoformat())
        results.append(_row("certs", status, host, target, detail))
    return results


# --- Cron: silent redirects, missing PATH, non-executable scripts ---


_CRON_ENV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _unquote_env(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def parse_cron_lines(text: str, source: str, system_style: bool) -> Dict[str, Any]:
    """Parse a crontab into env vars plus job dicts."""
    env: Dict[str, str] = {}
    jobs: List[Dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m_env = _CRON_ENV_RE.match(line)
        if m_env:
            env[m_env.group(1)] = _unquote_env(m_env.group(2))
            continue
        sched_m = re.match(
            r"^(@(?:reboot|yearly|annually|monthly|weekly|daily|hourly|midnight))\s+(.*)$",
            line,
            re.I,
        )
        if sched_m:
            schedule, rest = sched_m.group(1), sched_m.group(2)
            user = ""
            command = rest
            if system_style:
                bits = rest.split(None, 1)
                if len(bits) == 2:
                    user, command = bits[0], bits[1]
            jobs.append(
                {"source": source, "schedule": schedule, "user": user, "command": command, "raw": line}
            )
            continue
        parts = line.split(None, 5 if not system_style else 6)
        needed = 6 if not system_style else 7
        if len(parts) < needed:
            continue
        if system_style:
            jobs.append(
                {
                    "source": source,
                    "schedule": " ".join(parts[:5]),
                    "user": parts[5],
                    "command": parts[6],
                    "raw": line,
                }
            )
        else:
            jobs.append(
                {
                    "source": source,
                    "schedule": " ".join(parts[:5]),
                    "user": "",
                    "command": parts[5],
                    "raw": line,
                }
            )
    return {"env": env, "jobs": jobs}


def command_discards_all_output(command: str) -> Tuple[bool, bool]:
    """Return (stdout_discarded, stderr_discarded)."""
    cmd = command.strip()
    stdout = bool(re.search(r"(?:^|[&;|\s])&>\s*/dev/null", cmd)) or bool(
        re.search(r"(?:^|[&;|\s])>&\s*/dev/null", cmd)
    )
    both = bool(
        re.search(r">\s*/dev/null\s+2>&1", cmd)
        or re.search(r"2>\s*/dev/null\s+>\s*/dev/null", cmd)
        or re.search(r"2>&1\s+>\s*/dev/null", cmd)
        or re.search(r">\s*/dev/null\s+2>\s*/dev/null", cmd)
    )
    out = bool(re.search(r"(?:^|[&;|\s])>\s*/dev/null", cmd))
    err = bool(re.search(r"2>\s*/dev/null", cmd))
    if stdout or both:
        return True, True
    return out, err


def command_has_alerter(command: str) -> bool:
    tokens = re.split(r"[\s;|&<>]+", command)
    lower = [t.lower().rsplit("/", 1)[-1] for t in tokens if t]
    if any(t in CRON_ALERTERS or t.startswith("cronpulse") for t in lower):
        return True
    if re.search(r"https?://(hc-ping\.com|healthchecks\.io|ntfy\.sh)\b", command, re.I):
        return True
    return False


def first_command_token(command: str) -> str:
    rest = command.strip()
    while True:
        m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+(.*)$", rest)
        if not m:
            break
        rest = m.group(1)
    if rest.startswith("("):
        return ""
    return rest.split(None, 1)[0] if rest else ""


_INTERPRETERS = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "python", "python3", "python2", "perl", "ruby", "env"}
)


def script_path_to_check(command: str) -> Optional[str]:
    """If the job runs a script path directly, return that path."""
    token = first_command_token(command)
    if not token:
        return None
    base = token.rsplit("/", 1)[-1]
    if base in _INTERPRETERS:
        return None
    if token.startswith("/") or token.startswith("./") or token.startswith("~/"):
        return os.path.expanduser(token)
    return None


def check_cron_jobs(
    files: List[Dict[str, Any]],
    path_exists: Optional[Callable[[str], bool]] = None,
    path_executable: Optional[Callable[[str], bool]] = None,
) -> List[Dict[str, Any]]:
    exists = path_exists or os.path.exists
    executable = path_executable or (lambda p: os.path.isfile(p) and os.access(p, os.X_OK))
    results: List[Dict[str, Any]] = []
    for item in files:
        source = item["source"]
        parsed = parse_cron_lines(item.get("text") or "", source, bool(item.get("system_style")))
        env = parsed["env"]
        has_path = "PATH" in env
        mailto = env.get("MAILTO")
        for job in parsed["jobs"]:
            command = job["command"]
            target = (job["schedule"] + " " + command).strip()
            if len(target) > 90:
                target = target[:87] + "..."
            flags: List[Tuple[str, str]] = []
            out_d, err_d = command_discards_all_output(command)
            silent = out_d and err_d
            if silent and not command_has_alerter(command):
                flags.append((FAIL, "stdout and stderr go to /dev/null, no alert in the command"))
            elif (out_d or err_d) and not command_has_alerter(command):
                which = "stdout" if out_d else "stderr"
                flags.append((WARN, "%s goes to /dev/null" % which))
            if mailto == "" and not silent and not command_has_alerter(command):
                flags.append((WARN, "MAILTO is empty, cron will not mail output"))
            script = script_path_to_check(command)
            if script and exists(script) and not executable(script):
                flags.append((FAIL, "script is not executable: %s" % script))
            token = first_command_token(command)
            if (
                token
                and not token.startswith("/")
                and not token.startswith("./")
                and not token.startswith("~")
                and not has_path
            ):
                flags.append((WARN, "no PATH in this crontab, command is not an absolute path"))
            if not flags:
                results.append(_row("cron", OK, source, target, "no silent-fail signs"))
            else:
                flags.sort(key=lambda x: 0 if x[0] == FAIL else 1)
                status = flags[0][0]
                detail = "; ".join(d for _, d in flags)
                results.append(_row("cron", status, source, target, detail))
    if not results:
        results.append(_row("cron", OK, "cron", "-", "no cron jobs found (or none were readable)"))
    return results


def collect_cron_files(
    extra_texts: Optional[List[Dict[str, Any]]] = None,
    cron_paths: Optional[List[Tuple[str, bool]]] = None,
    user_crontab: Optional[str] = None,
) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = list(extra_texts or [])
    if extra_texts is not None and cron_paths is None and user_crontab is None:
        return files
    paths = cron_paths
    if paths is None:
        paths = [("/etc/crontab", True)]
        try:
            for name in sorted(os.listdir("/etc/cron.d")):
                if name.startswith(".") or name in ("README", "placeholder"):
                    continue
                paths.append((os.path.join("/etc/cron.d", name), True))
        except OSError:
            pass
        for spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
            try:
                for name in sorted(os.listdir(spool)):
                    if name.startswith("."):
                        continue
                    paths.append((os.path.join(spool, name), False))
            except OSError:
                continue
    for path, system_style in paths:
        text = read_text(path)
        if text is None:
            continue
        files.append({"source": path, "text": text, "system_style": system_style})
    if user_crontab is None:
        user_crontab = run_cmd(["crontab", "-l"])
    if user_crontab and "no crontab for" not in user_crontab.lower():
        files.append({"source": "user crontab", "text": user_crontab, "system_style": False})
    return files



# --- Disk + Docker disk ---


def iter_mounts(mounts_text: Optional[str] = None) -> List[Tuple[str, str]]:
    """Return [(mountpoint, fstype)] for real filesystems, shortest path first."""
    text = mounts_text if mounts_text is not None else read_text("/proc/mounts")
    if not text:
        return [("/", "unknown")]
    rows = []
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        _dev, mp, fstype = parts[0], parts[1], parts[2]
        mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), mp)
        if fstype not in DISK_FS:
            continue
        if mp in seen:
            continue
        seen.add(mp)
        rows.append((mp, fstype))
    rows.sort(key=lambda r: (r[0].count("/"), r[0]))
    if not any(mp == "/" for mp, _ in rows):
        rows.insert(0, ("/", "unknown"))
    return rows


def usage_percent(total: int, used: int) -> int:
    if total <= 0:
        return 0
    return int(used * 100 / total)


def classify_percent(pct: int, warn: int, fail: int) -> str:
    if pct >= fail:
        return FAIL
    if pct >= warn:
        return WARN
    return OK


def human_bytes(n: int) -> str:
    if n < 0:
        n = 0
    units = ("B", "K", "M", "G", "T", "P")
    value = float(n)
    unit = units[0]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            break
        value /= 1024.0
    if unit == "B":
        return "%dB" % n
    return "%.1f%s" % (value, unit)


def check_disk(
    mounts: Optional[List[Tuple[str, str]]] = None,
    usages: Optional[Dict[str, Tuple[int, int, int]]] = None,
    warn: int = DEFAULT_DISK_WARN,
    fail: int = DEFAULT_DISK_FAIL,
    docker_usage: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """usages maps mountpoint -> (total, used, free) bytes."""
    if mounts is None:
        mounts = iter_mounts()
    results: List[Dict[str, Any]] = []
    for mp, fstype in mounts:
        try:
            if usages is not None:
                if mp not in usages:
                    continue
                total, used, free = usages[mp]
            else:
                du = shutil.disk_usage(mp)
                total, used, free = du.total, du.used, du.free
        except OSError as exc:
            results.append(_row("disk", ERROR, mp, mp, "cannot read disk usage: %s" % exc))
            continue
        pct = usage_percent(total, used)
        status = classify_percent(pct, warn, fail)
        detail = "%d%% used (%s of %s, fstype %s)" % (pct, human_bytes(used), human_bytes(total), fstype)
        if status == FAIL:
            detail += " — over the %d%% fail threshold" % fail
        elif status == WARN:
            detail += " — over the %d%% warn threshold" % warn
        results.append(_row("disk", status, mp, mp, detail))
    if docker_usage:
        results.extend(_docker_disk_rows(docker_usage, warn, fail))
    if not results:
        results.append(_row("disk", ERROR, "disk", "-", "no filesystems could be checked"))
    return results


def _docker_disk_rows(info: Dict[str, Any], warn: int, fail: int) -> List[Dict[str, Any]]:
    rows = []
    pct = info.get("percent")
    root = info.get("root") or "/var/lib/docker"
    if pct is not None:
        status = classify_percent(int(pct), warn, fail)
        detail = "%d%% of the filesystem holding %s" % (int(pct), root)
        extra = info.get("breakdown")
        if extra:
            detail += " (%s)" % extra
        if status == FAIL:
            detail += " — over the %d%% fail threshold" % fail
        elif status == WARN:
            detail += " — over the %d%% warn threshold" % warn
        rows.append(_row("disk", status, "docker", root, detail))
    elif info.get("breakdown"):
        rows.append(_row("disk", OK, "docker", root, info["breakdown"]))
    if info.get("error"):
        rows.append(_row("disk", ERROR, "docker", root, info["error"]))
    return rows


def collect_docker_disk(
    docker: Any, usages: Optional[Dict[str, Tuple[int, int, int]]] = None
) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {"root": "/var/lib/docker"}
    try:
        info = docker.info() if docker is not None else {}
    except DockerError as exc:
        return {"root": "/var/lib/docker", "error": "cannot read Docker info: %s" % exc}
    root = (info or {}).get("DockerRootDir") or "/var/lib/docker"
    out["root"] = root
    try:
        if usages is not None and root in usages:
            total, used, _free = usages[root]
        else:
            du = shutil.disk_usage(root)
            total, used = du.total, du.used
        out["percent"] = usage_percent(total, used)
    except OSError:
        pass
    try:
        df = docker.system_df() if docker is not None else {}
    except DockerError:
        df = {}
    parts = []
    for label, key in (
        ("images", "Images"),
        ("containers", "Containers"),
        ("volumes", "Volumes"),
        ("build cache", "BuildCache"),
    ):
        entries = (df or {}).get(key) or []
        total_size = 0
        for item in entries:
            if isinstance(item, dict):
                total_size += int(item.get("Size") or (item.get("UsageData") or {}).get("Size") or 0)
        if entries or total_size:
            parts.append("%s %s" % (human_bytes(total_size), label))
    if (df or {}).get("LayersSize"):
        parts.insert(0, "%s layers" % human_bytes(int(df["LayersSize"])))
    if parts:
        out["breakdown"] = ", ".join(parts)
    return out


# --- Offline demo ---


class DemoRegistry:
    """Canned registry answers for --demo (no network)."""

    DIGESTS = {
        "docker.io/gitea/gitea:1.21.0": "sha256:" + "a1" * 32,
        "docker.io/library/redis:7.2-alpine": "sha256:" + "d4" * 32,
        "docker.io/library/traefik:v2.10.4": "sha256:" + "c3" * 32,
    }
    TAGS = {
        "docker.io/gitea/gitea": ["1.20.5", "1.21.0", "1.21.3", "latest", "1.22.0-rc1"],
        "docker.io/library/redis": ["7.2-alpine", "7.4-alpine", "7.2"],
        "docker.io/library/traefik": ["v2.10.3", "v2.10.4", "v3.0", "latest"],
    }

    def remote_digest(self, ref: ImageRef) -> str:
        return self.DIGESTS[ref.key]

    def list_tags(self, ref: ImageRef, max_pages: int = 3) -> List[str]:
        return self.TAGS.get("%s/%s" % (ref.registry, ref.repository), [])


DEMO_CONTAINERS = [
    {"name": "gitea", "image": "gitea/gitea:1.21.0", "local_digest": "sha256:" + "a1" * 32},
    {"name": "redis-cache", "image": "redis:7.2-alpine", "local_digest": "sha256:" + "b2" * 32},
    {"name": "traefik", "image": "traefik:v2.10.4", "local_digest": "sha256:" + "c3" * 32},
    {"name": "my-app", "image": "my-app:dev", "local_digest": None},
]

DEMO_DOCKER_LIST = [
    {
        "Names": ["/postgres"],
        "Ports": [{"IP": "0.0.0.0", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"}],
    },
    {
        "Names": ["/gitea"],
        "Ports": [{"IP": "127.0.0.1", "PrivatePort": 3000, "PublicPort": 3000, "Type": "tcp"}],
    },
]

DEMO_LISTENERS = [
    {"proto": "tcp", "ip": "0.0.0.0", "port": "22", "process": "sshd"},
    {"proto": "tcp", "ip": "0.0.0.0", "port": "5432", "process": "docker-proxy"},
    {"proto": "tcp", "ip": "127.0.0.1", "port": "3000", "process": "docker-proxy"},
    {"proto": "tcp", "ip": "127.0.0.1", "port": "8080", "process": "caddy"},
]

DEMO_CERTS = {
    ("vault.lab.example", 443): DEMO_NOW + timedelta(days=80),
    ("blog.lab.example", 443): DEMO_NOW + timedelta(days=12),
    ("expired.lab.example", 443): DEMO_NOW - timedelta(days=4),
}

DEMO_CRON = [
    {
        "source": "/etc/crontab",
        "system_style": True,
        "text": (
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "MAILTO=alessio@example.com\n"
            "0 6 * * * root /usr/bin/apt-get update -qq\n"
        ),
    },
    {
        "source": "/etc/cron.d/backup",
        "system_style": True,
        "text": "0 3 * * * root /opt/backup.sh >/dev/null 2>&1\n",
    },
    {"source": "user crontab", "system_style": False, "text": "0 4 * * * backup.sh\n"},
    {
        "source": "/etc/cron.d/sync",
        "system_style": True,
        "text": "PATH=/usr/bin:/bin\n0 5 * * * root /usr/local/bin/sync.sh\n",
    },
]

DEMO_MOUNTS = [("/", "ext4"), ("/boot", "ext4"), ("/var", "ext4")]
DEMO_USAGE = {
    "/": (100 * 1024 ** 3, 93 * 1024 ** 3, 7 * 1024 ** 3),
    "/boot": (1 * 1024 ** 3, int(0.41 * 1024 ** 3), int(0.59 * 1024 ** 3)),
    "/var": (50 * 1024 ** 3, 42 * 1024 ** 3, 8 * 1024 ** 3),
}
DEMO_DOCKER_DISK = {
    "root": "/var/lib/docker",
    "percent": 81,
    "breakdown": "8.0G layers, 6.1G images, 1.4G volumes, 800.0M build cache",
}


def _demo_fetch(host: str, port: int) -> Dict[str, Any]:
    expiry = DEMO_CERTS[(host, port)]
    stamp = expiry.astimezone(timezone.utc).strftime("%b %d %H:%M:%S %Y GMT")
    return {"notAfter": stamp}


def run_demo(
    skips: Iterable[str], warn_days: int, fail_days: int, disk_warn: int, disk_fail: int
) -> List[Dict[str, Any]]:
    skips_set = set(skips)
    rows: List[Dict[str, Any]] = []
    if "images" not in skips_set:
        rows.extend(check_images(DEMO_CONTAINERS, DemoRegistry(), tag_check=True))
    if "ports" not in skips_set:
        rows.extend(
            check_ports(
                DEMO_LISTENERS,
                docker_published_ports(DEMO_DOCKER_LIST),
                firewall={"name": "ufw", "state": "active", "label": "UFW is active"},
            )
        )
    if "certs" not in skips_set:
        rows.extend(
            check_certs(
                list(DEMO_CERTS.keys()),
                now=DEMO_NOW,
                warn_days=warn_days,
                fail_days=fail_days,
                fetch=_demo_fetch,
            )
        )
    if "cron" not in skips_set:
        rows.extend(
            check_cron_jobs(
                DEMO_CRON,
                path_exists=lambda p: p in ("/usr/local/bin/sync.sh", "/opt/backup.sh"),
                path_executable=lambda p: p == "/opt/backup.sh",
            )
        )
    if "disk" not in skips_set:
        rows.extend(
            check_disk(
                mounts=DEMO_MOUNTS,
                usages=DEMO_USAGE,
                warn=disk_warn,
                fail=disk_fail,
                docker_usage=DEMO_DOCKER_DISK,
            )
        )
    return rows



# --- Report + exit code ---


SECTION_TITLES = {
    "images": "Images",
    "ports": "Ports",
    "certs": "Certificates",
    "cron": "Cron",
    "disk": "Disk",
}


def render(rows: List[Dict[str, Any]], header: str) -> str:
    lines = [header, ""]
    for check in CHECKS:
        section = [r for r in rows if r.get("check") == check]
        if not section:
            continue
        lines.append(SECTION_TITLES[check])
        wn = max(len(r.get("name") or "") for r in section)
        wt = max(len(r.get("target") or "") for r in section)
        wn = min(max(wn, 4), 28)
        wt = min(max(wt, 4), 52)
        for r in section:
            name = (r.get("name") or "")[:wn]
            target = (r.get("target") or "")[:wt]
            lines.append(
                "  %-5s  %-*s  %-*s  %s" % (r["status"], wn, name, wt, target, r.get("detail") or "")
            )
        lines.append("")
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    n_checks = len({r["check"] for r in rows})
    lines.append(
        "%d check(s), %d finding(s): %d FAIL, %d WARN, %d OK, %d skipped, %d could not be checked."
        % (
            n_checks,
            counts[FAIL] + counts[WARN],
            counts[FAIL],
            counts[WARN],
            counts[OK],
            counts[SKIP],
            counts[ERROR],
        )
    )
    lines.append("Read-only: nothing was changed on this host.")
    return "\n".join(lines)


def exit_code(rows: List[Dict[str, Any]], enabled: Sequence[str]) -> int:
    if any(r["status"] in (FAIL, WARN) for r in rows):
        return 1
    enabled_set = set(enabled)
    by_check: Dict[str, List[Dict[str, Any]]] = {c: [] for c in enabled_set}
    for r in rows:
        if r.get("check") in by_check:
            by_check[r["check"]].append(r)
    ran = False
    all_error = True
    for check in enabled_set:
        section = by_check.get(check) or []
        useful = [r for r in section if r["status"] != SKIP]
        if not useful:
            if section:
                ran = True
                all_error = False
            continue
        ran = True
        if not all(r["status"] == ERROR for r in useful):
            all_error = False
    if not ran or all_error:
        return 2
    return 0


def parse_skips(values: Optional[Sequence[str]]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        for part in v.split(","):
            item = part.strip().lower()
            if not item:
                continue
            if item not in CHECKS:
                raise ValueError("unknown check %r (choose from: %s)" % (item, ", ".join(CHECKS)))
            if item not in out:
                out.append(item)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="homelab-doctor",
        description=(
            "Read-only health check for a self-hosted / homelab box: stale Docker images, "
            "ports on all interfaces (including Docker publications that often bypass the "
            "host firewall), TLS certificates about to expire, cron jobs that look like "
            "they fail silently, and disk usage. Exit 0 = nothing to flag, 1 = WARN or "
            "FAIL, 2 = error."
        ),
        epilog="Full tools with alerts and deeper audits: " + SITE + "/?" + UTM,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="CHECK",
        help="skip one or more checks: images,ports,certs,cron,disk (comma-separated, repeatable)",
    )
    p.add_argument(
        "--cert",
        action="append",
        default=[],
        metavar="HOST[:PORT]",
        help="TLS host to check (default port 443). Repeatable. Needed for the certs check "
        "unless you also pass --certs-file",
    )
    p.add_argument("--certs-file", metavar="PATH", help="file of host:port lines (# comments allowed)")
    p.add_argument(
        "--cert-warn-days",
        type=int,
        default=DEFAULT_CERT_WARN_DAYS,
        help="WARN when a certificate expires within this many days (default: %d)" % DEFAULT_CERT_WARN_DAYS,
    )
    p.add_argument(
        "--cert-fail-days",
        type=int,
        default=DEFAULT_CERT_FAIL_DAYS,
        help="FAIL when a certificate expires within this many days (default: %d)" % DEFAULT_CERT_FAIL_DAYS,
    )
    p.add_argument(
        "--disk-warn",
        type=int,
        default=DEFAULT_DISK_WARN,
        help="WARN at this used-percent (default: %d)" % DEFAULT_DISK_WARN,
    )
    p.add_argument(
        "--disk-fail",
        type=int,
        default=DEFAULT_DISK_FAIL,
        help="FAIL at this used-percent (default: %d)" % DEFAULT_DISK_FAIL,
    )
    p.add_argument(
        "--socket",
        default=None,
        help="Docker socket path (default: DOCKER_HOST if it is unix://..., else %s)" % DEFAULT_SOCKET,
    )
    p.add_argument("--no-tags", action="store_true", help="image check: compare digests only, skip newer-tag lookup")
    p.add_argument(
        "--demo",
        action="store_true",
        help="offline demo with sample data (no Docker, no network, no host changes)",
    )
    p.add_argument("--timeout", type=float, default=10, help="network and command timeout in seconds (default: 10)")
    p.add_argument("--version", action="version", version="homelab-doctor " + __version__)
    return p


def main(argv: Optional[List[str]] = None, **hooks: Any) -> int:
    """hooks let tests inject docker/registry/listeners/cron/disk without touching the host."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2

    if args.timeout <= 0:
        print("error: --timeout must be > 0", file=sys.stderr)
        return 2
    if args.cert_warn_days < 0 or args.cert_fail_days < 0:
        print("error: certificate day thresholds must be >= 0", file=sys.stderr)
        return 2
    if args.cert_fail_days > args.cert_warn_days:
        print("error: --cert-fail-days must be <= --cert-warn-days", file=sys.stderr)
        return 2
    if not (0 <= args.disk_warn <= 100 and 0 <= args.disk_fail <= 100):
        print("error: disk thresholds must be between 0 and 100", file=sys.stderr)
        return 2
    if args.disk_warn > args.disk_fail:
        print("error: --disk-warn must be <= --disk-fail", file=sys.stderr)
        return 2

    try:
        skips = parse_skips(args.skip)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    enabled = [c for c in CHECKS if c not in skips]
    if not enabled:
        print("error: every check was skipped", file=sys.stderr)
        return 2

    if args.demo:
        rows = run_demo(skips, args.cert_warn_days, args.cert_fail_days, args.disk_warn, args.disk_fail)
        print(
            render(
                rows,
                "homelab-doctor %s: demo (sample data, no Docker, no network, nothing changed)"
                % __version__,
            )
        )
        return exit_code(rows, enabled)

    sock = args.socket or default_socket()
    docker = hooks.get("docker")
    docker_error: Optional[str] = None
    containers: List[Dict[str, Any]] = []
    need_docker = any(c in enabled for c in ("images", "ports", "disk"))
    if need_docker and docker is None:
        docker = DockerClient(sock, timeout=min(args.timeout, 10))
    if need_docker and docker is not None and hooks.get("containers") is None:
        try:
            containers = docker.list_containers()
        except DockerError as exc:
            docker_error = str(exc)
            containers = []
    elif hooks.get("containers") is not None:
        containers = hooks["containers"]

    rows: List[Dict[str, Any]] = []

    if "images" in enabled:
        if docker_error and hooks.get("image_containers") is None:
            rows.append(_row("images", ERROR, "docker", sock, docker_error))
        else:
            image_containers = hooks.get("image_containers")
            if image_containers is None:
                if docker is not None and not docker_error:
                    try:
                        image_containers = running_containers(docker)
                    except DockerError as exc:
                        rows.append(_row("images", ERROR, "docker", sock, str(exc)))
                        image_containers = None
                else:
                    image_containers = []
            if image_containers is not None:
                registry = hooks.get("registry") or RegistryClient(timeout=args.timeout)
                rows.extend(check_images(image_containers, registry, tag_check=not args.no_tags))

    if "ports" in enabled:
        listeners = hooks.get("listeners")
        if listeners is None:
            listeners = collect_listen_ports()
        published: List[Dict[str, str]] = []
        if docker_error and hooks.get("published") is None:
            rows.append(_row("ports", ERROR, "docker", sock, "Docker publications skipped: %s" % docker_error))
        else:
            published = (
                hooks.get("published") if hooks.get("published") is not None else docker_published_ports(containers)
            )
        fw = hooks.get("firewall") if "firewall" in hooks else detect_firewall()
        rows.extend(check_ports(listeners, published, firewall=fw))

    if "certs" in enabled:
        try:
            if hooks.get("cert_targets") is not None:
                targets = hooks["cert_targets"]
            else:
                targets = load_cert_targets(args.cert, args.certs_file)
        except (OSError, ValueError) as exc:
            rows.append(_row("certs", ERROR, "certs", "-", str(exc)))
        else:
            rows.extend(
                check_certs(
                    targets,
                    now=hooks.get("now"),
                    warn_days=args.cert_warn_days,
                    fail_days=args.cert_fail_days,
                    fetch=hooks.get("fetch_cert"),
                    timeout=args.timeout,
                )
            )

    if "cron" in enabled:
        cron_files = hooks.get("cron_files") if hooks.get("cron_files") is not None else collect_cron_files()
        rows.extend(
            check_cron_jobs(
                cron_files,
                path_exists=hooks.get("path_exists"),
                path_executable=hooks.get("path_executable"),
            )
        )

    if "disk" in enabled:
        docker_usage = hooks.get("docker_usage")
        if docker_usage is None and docker is not None and not docker_error:
            docker_usage = collect_docker_disk(docker, usages=hooks.get("usages"))
        elif docker_usage is None and docker_error:
            docker_usage = {"root": "/var/lib/docker", "error": "Docker disk skipped: %s" % docker_error}
        rows.extend(
            check_disk(
                mounts=hooks.get("mounts"),
                usages=hooks.get("usages"),
                warn=args.disk_warn,
                fail=args.disk_fail,
                docker_usage=docker_usage,
            )
        )

    print(render(rows, "homelab-doctor %s" % __version__))
    return exit_code(rows, enabled)


if __name__ == "__main__":
    sys.exit(main())
