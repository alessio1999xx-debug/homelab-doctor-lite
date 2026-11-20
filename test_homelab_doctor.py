"""Offline tests for homelab-doctor (no network, no Docker required)."""
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

import homelab_doctor as hd


def run(*argv, **hooks):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = hd.main(list(argv), **hooks)
    return code, out.getvalue(), err.getvalue()


class FakeRegistry:
    def __init__(self, digests=None, tags=None, fail=None):
        self.digests, self.tags, self.fail = digests or {}, tags or {}, fail or {}

    def remote_digest(self, ref):
        if ref.key in self.fail:
            raise RuntimeError(self.fail[ref.key])
        return self.digests[ref.key]

    def list_tags(self, ref, max_pages=3):
        return self.tags.get(ref.registry + "/" + ref.repository, [])


class FakeDocker:
    def __init__(self, containers=None, images=None, error=None, info=None, df=None):
        self.containers = containers or []
        self.images = images or {}
        self.error = error
        self._info = info or {}
        self._df = df or {}

    def list_containers(self):
        if self.error:
            raise hd.DockerError(self.error)
        return self.containers

    def inspect_image(self, image_id):
        return self.images.get(image_id)

    def info(self):
        if self.error:
            raise hd.DockerError(self.error)
        return self._info

    def system_df(self):
        return self._df


class TestImageRef(unittest.TestCase):
    def test_docker_hub_official(self):
        ref = hd.ImageRef("redis:7.2-alpine")
        self.assertEqual(ref.registry, "docker.io")
        self.assertEqual(ref.repository, "library/redis")
        self.assertEqual(ref.tag, "7.2-alpine")
        self.assertEqual(ref.key, "docker.io/library/redis:7.2-alpine")

    def test_named_and_digest(self):
        ref = hd.ImageRef("gitea/gitea:1.21.0")
        self.assertEqual(ref.repository, "gitea/gitea")
        pinned = hd.ImageRef("redis@sha256:" + "ab" * 32)
        self.assertTrue(pinned.digest.startswith("sha256:"))
        self.assertFalse(pinned.tag_given)

    def test_newer_tag_same_style(self):
        self.assertEqual(hd.find_newer_tag("1.21.0", ["1.20.5", "1.21.0", "1.21.3", "1.22.0-rc1"]), "1.21.3")
        self.assertEqual(hd.find_newer_tag("7.2-alpine", ["7.2-alpine", "7.4-alpine", "7.2"]), "7.4-alpine")
        self.assertIsNone(hd.find_newer_tag("v2.10.4", ["v2.10.3", "v2.10.4", "v3.0", "latest"]))
        self.assertIsNone(hd.find_newer_tag("latest", ["1.0", "2.0"]))


class TestImages(unittest.TestCase):
    def test_warn_on_newer_tag_and_digest(self):
        registry = FakeRegistry(
            digests={
                "docker.io/gitea/gitea:1.21.0": "sha256:" + "a1" * 32,
                "docker.io/library/redis:7.2-alpine": "sha256:" + "d4" * 32,
            },
            tags={
                "docker.io/gitea/gitea": ["1.21.0", "1.21.3"],
                "docker.io/library/redis": ["7.2-alpine", "7.4-alpine"],
            },
        )
        rows = hd.check_images(
            [
                {"name": "gitea", "image": "gitea/gitea:1.21.0", "local_digest": "sha256:" + "a1" * 32},
                {"name": "redis", "image": "redis:7.2-alpine", "local_digest": "sha256:" + "b2" * 32},
            ],
            registry,
        )
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["gitea"]["status"], hd.WARN)
        self.assertIn("newer tag 1.21.3", by["gitea"]["detail"])
        self.assertEqual(by["redis"]["status"], hd.WARN)
        self.assertIn("new digest", by["redis"]["detail"])

    def test_skip_local_image(self):
        rows = hd.check_images([{"name": "app", "image": "my-app:dev", "local_digest": None}], FakeRegistry())
        self.assertEqual(rows[0]["status"], hd.SKIP)


class TestPorts(unittest.TestCase):
    def test_parse_ss(self):
        # ss -lnt (no Netid column)
        text = (
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
            "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n"
            "LISTEN 0 128 *:80 0.0.0.0:*\n"
            "LISTEN 0 128 [::]:443 [::]:*\n"
        )
        rows = hd.parse_ss_listen(text)
        self.assertEqual(len(rows), 4)
        ssh = next(r for r in rows if r["port"] == "22")
        self.assertEqual(ssh["process"], "sshd")
        self.assertTrue(hd.is_wildcard_ip(next(r for r in rows if r["port"] == "80")["ip"]))
        # ss -lntuh (Netid column first)
        text2 = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            "tcp   LISTEN 0      128        0.0.0.0:22         0.0.0.0:*\n"
            "tcp   LISTEN 0      128          *:80            0.0.0.0:*\n"
            "udp   UNCONN 0        0        0.0.0.0:53         0.0.0.0:*\n"
        )
        rows2 = hd.parse_ss_listen(text2)
        self.assertEqual(sorted((r["proto"], r["port"]) for r in rows2), [("tcp", "22"), ("tcp", "80"), ("udp", "53")])

    def test_parse_proc_tcp_listen(self):
        # 0100007F:1F90 is 127.0.0.1:8080; 00000000:0016 is 0.0.0.0:22
        text = (
            "  sl  local_address rem_address   st\n"
            "   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n"
            "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n"
            "   2: 00000000:0050 00000000:0000 01 00000000:00000000\n"
        )
        rows = hd.parse_proc_net(text)
        ports = {r["port"]: r for r in rows}
        self.assertIn("22", ports)
        self.assertEqual(ports["22"]["ip"], "0.0.0.0")
        self.assertEqual(ports["8080"]["ip"], "127.0.0.1")
        self.assertNotIn("80", ports)  # state 01 is not LISTEN

    def test_docker_bypass_is_fail_when_firewall_active(self):
        listeners = [
            {"proto": "tcp", "ip": "0.0.0.0", "port": "5432", "process": "docker-proxy"},
            {"proto": "tcp", "ip": "0.0.0.0", "port": "22", "process": "sshd"},
            {"proto": "tcp", "ip": "127.0.0.1", "port": "3000", "process": "caddy"},
        ]
        published = hd.docker_published_ports(
            [{"Names": ["/postgres"], "Ports": [{"IP": "0.0.0.0", "PublicPort": 5432, "PrivatePort": 5432, "Type": "tcp"}]}]
        )
        rows = hd.check_ports(
            listeners, published, firewall={"name": "ufw", "state": "active", "label": "UFW is active"}
        )
        by_port = {r["target"]: r for r in rows}
        pg = next(r for r in rows if r["target"].startswith("0.0.0.0:5432"))
        self.assertEqual(pg["status"], hd.FAIL)
        self.assertIn("bypass", pg["detail"].lower())
        ssh = next(r for r in rows if r["target"].startswith("0.0.0.0:22"))
        self.assertEqual(ssh["status"], hd.WARN)
        loop = next(r for r in rows if "3000" in r["target"])
        self.assertEqual(loop["status"], hd.OK)
        # docker-proxy on 5432 is not double-counted
        self.assertEqual(sum(1 for r in rows if "5432" in r["target"]), 1)

    def test_wildcard_docker_is_warn_without_firewall(self):
        published = hd.docker_published_ports(
            [{"Names": ["/web"], "Ports": [{"IP": "0.0.0.0", "PublicPort": 80, "Type": "tcp"}]}]
        )
        rows = hd.check_ports([], published, firewall={"name": "", "state": "unknown", "label": "no host firewall detected"})
        self.assertEqual(rows[0]["status"], hd.WARN)


class TestCerts(unittest.TestCase):
    def test_parse_hostport(self):
        self.assertEqual(hd.parse_hostport("example.com"), ("example.com", 443))
        self.assertEqual(hd.parse_hostport("example.com:8443"), ("example.com", 8443))
        self.assertEqual(hd.parse_hostport("[::1]:443"), ("::1", 443))

    def test_certs_file_and_classification(self):
        now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)

        def stamp(days):
            expiry = now + timedelta(days=days)
            return {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")}

        table = {
            ("ok.example", 443): stamp(80),
            ("warn.example", 443): stamp(12),
            ("fail.example", 443): stamp(3),
            ("dead.example", 443): stamp(-4),
        }
        text = "# comment\ncert ok.example\nwarn.example:443\nfail.example:443\ndead.example:443\n"
        targets = hd.load_cert_targets([], certs_file="unused", file_text=text)
        rows = hd.check_certs(targets, now=now, fetch=lambda h, p: table[(h, p)])
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["ok.example"]["status"], hd.OK)
        self.assertEqual(by["warn.example"]["status"], hd.WARN)
        self.assertEqual(by["fail.example"]["status"], hd.FAIL)
        self.assertEqual(by["dead.example"]["status"], hd.FAIL)
        self.assertIn("expired 4 days ago", by["dead.example"]["detail"])

    def test_skip_when_no_hosts(self):
        rows = hd.check_certs([])
        self.assertEqual(rows[0]["status"], hd.SKIP)


class TestCron(unittest.TestCase):
    def test_silent_redirect_is_fail(self):
        files = [
            {
                "source": "/etc/cron.d/backup",
                "system_style": True,
                "text": "PATH=/usr/bin:/bin\n0 3 * * * root /opt/backup.sh >/dev/null 2>&1\n",
            }
        ]
        rows = hd.check_cron_jobs(files, path_exists=lambda p: False, path_executable=lambda p: False)
        self.assertEqual(rows[0]["status"], hd.FAIL)
        self.assertIn("/dev/null", rows[0]["detail"])

    def test_alerter_overrides_redirect(self):
        files = [
            {
                "source": "user crontab",
                "system_style": False,
                "text": "PATH=/usr/bin:/bin\n0 3 * * * cronpulse run -- /opt/backup.sh >/dev/null 2>&1\n",
            }
        ]
        rows = hd.check_cron_jobs(files, path_exists=lambda p: False, path_executable=lambda p: False)
        self.assertEqual(rows[0]["status"], hd.OK)

    def test_missing_path_and_non_executable(self):
        files = [
            {"source": "user crontab", "system_style": False, "text": "0 4 * * * backup.sh\n"},
            {
                "source": "/etc/cron.d/sync",
                "system_style": True,
                "text": "PATH=/usr/bin:/bin\n0 5 * * * root /usr/local/bin/sync.sh\n",
            },
        ]
        rows = hd.check_cron_jobs(
            files,
            path_exists=lambda p: p == "/usr/local/bin/sync.sh",
            path_executable=lambda p: False,
        )
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["user crontab"]["status"], hd.WARN)
        self.assertIn("PATH", by["user crontab"]["detail"])
        self.assertEqual(by["/etc/cron.d/sync"]["status"], hd.FAIL)
        self.assertIn("not executable", by["/etc/cron.d/sync"]["detail"])

    def test_stdout_only_is_warn(self):
        files = [
            {
                "source": "/etc/crontab",
                "system_style": True,
                "text": "PATH=/usr/bin\n0 1 * * * root /usr/bin/do-thing > /dev/null\n",
            }
        ]
        rows = hd.check_cron_jobs(files)
        self.assertEqual(rows[0]["status"], hd.WARN)


class TestDisk(unittest.TestCase):
    def test_thresholds_and_human_bytes(self):
        self.assertEqual(hd.human_bytes(1024), "1.0K")
        self.assertEqual(hd.classify_percent(79, 80, 90), hd.OK)
        self.assertEqual(hd.classify_percent(80, 80, 90), hd.WARN)
        self.assertEqual(hd.classify_percent(90, 80, 90), hd.FAIL)
        usages = {
            "/": (100 * 1024 ** 3, 93 * 1024 ** 3, 7 * 1024 ** 3),
            "/boot": (1024 ** 3, int(0.41 * 1024 ** 3), int(0.59 * 1024 ** 3)),
        }
        rows = hd.check_disk(
            mounts=[("/", "ext4"), ("/boot", "ext4")],
            usages=usages,
            docker_usage={"root": "/var/lib/docker", "percent": 81, "breakdown": "8.0G layers"},
        )
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["/"]["status"], hd.FAIL)
        self.assertEqual(by["/boot"]["status"], hd.OK)
        self.assertEqual(by["docker"]["status"], hd.WARN)

    def test_iter_mounts_skips_tmpfs(self):
        text = (
            "sysfs /sys sysfs rw 0 0\n"
            "/dev/sda1 / ext4 rw 0 0\n"
            "tmpfs /tmp tmpfs rw 0 0\n"
            "/dev/sda2 /boot ext4 rw 0 0\n"
        )
        mounts = hd.iter_mounts(text)
        self.assertEqual(mounts, [("/", "ext4"), ("/boot", "ext4")])


class TestCLI(unittest.TestCase):
    def test_demo_exits_1_and_shows_all_sections(self):
        code, out, err = run("--demo")
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        for title in ("Images", "Ports", "Certificates", "Cron", "Disk"):
            self.assertIn(title, out)
        self.assertIn("homelab-doctor 0.1.0: demo", out)
        self.assertIn("Read-only: nothing was changed on this host.", out)
        self.assertIn("newer tag 1.21.3", out)
        self.assertIn("UFW is active", out)
        self.assertIn("expired 4 days ago", out)
        self.assertIn("/dev/null", out)
        self.assertIn("93% used", out)

    def test_skip_and_unknown_check(self):
        code, out, err = run("--demo", "--skip", "images,ports", "--skip", "certs")
        self.assertEqual(code, 1)
        self.assertNotIn("\nImages\n", "\n" + out)
        self.assertIn("Cron", out)
        code, out, err = run("--demo", "--skip", "images,nope")
        self.assertEqual(code, 2)
        self.assertIn("unknown check", err)

    def test_skip_all_is_error(self):
        code, out, err = run("--demo", "--skip", "images,ports,certs,cron,disk")
        self.assertEqual(code, 2)
        self.assertIn("every check was skipped", err)

    def test_bad_thresholds(self):
        code, _, err = run("--demo", "--disk-warn", "95", "--disk-fail", "80")
        self.assertEqual(code, 2)
        self.assertIn("--disk-warn", err)
        code, _, err = run("--demo", "--cert-fail-days", "40", "--cert-warn-days", "30")
        self.assertEqual(code, 2)
        self.assertIn("--cert-fail-days", err)

    def test_help_and_version(self):
        code, out, err = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("Read-only health check", out)
        code, out, err = run("--version")
        self.assertEqual(code, 0)
        self.assertIn("homelab-doctor 0.1.0", out + err)

    def test_live_hooks_ok_exit_zero(self):
        now = datetime(2026, 11, 20, tzinfo=timezone.utc)
        expiry = now + timedelta(days=80)
        docker = FakeDocker(containers=[], info={"DockerRootDir": "/"}, df={})
        code, out, err = run(
            "--cert",
            "ok.example",
            "--skip",
            "images",
            docker=docker,
            listeners=[{"proto": "tcp", "ip": "127.0.0.1", "port": "22", "process": "sshd"}],
            published=[],
            firewall={"name": "ufw", "state": "inactive", "label": "UFW is inactive"},
            fetch_cert=lambda h, p: {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")},
            now=now,
            cron_files=[
                {
                    "source": "/etc/crontab",
                    "system_style": True,
                    "text": "PATH=/usr/bin:/bin\n0 1 * * * root /usr/bin/true\n",
                }
            ],
            mounts=[("/", "ext4")],
            usages={"/": (100 * 1024 ** 3, 10 * 1024 ** 3, 90 * 1024 ** 3)},
            docker_usage={"root": "/", "percent": 10, "breakdown": "1.0G layers"},
        )
        self.assertEqual(err, "")
        self.assertEqual(code, 0)
        self.assertIn("  OK ", out)

    def test_certs_file_roundtrip(self):
        now = datetime(2026, 11, 20, tzinfo=timezone.utc)
        expiry = now + timedelta(days=80)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "certs.txt"
            path.write_text("ok.example:443\n", encoding="utf-8")
            code, out, err = run(
                "--certs-file",
                str(path),
                "--skip",
                "images,ports,cron,disk",
                fetch_cert=lambda h, p: {"notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT")},
                now=now,
            )
        self.assertEqual(code, 0)
        self.assertIn("ok.example", out)

    def test_exit_code_all_errors(self):
        rows = [hd._row("images", hd.ERROR, "docker", "-", "no socket")]
        self.assertEqual(hd.exit_code(rows, ["images"]), 2)
        self.assertEqual(hd.exit_code([hd._row("certs", hd.SKIP, "certs", "-", "no hosts")], ["certs"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
