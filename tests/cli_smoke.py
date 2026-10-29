"""Exercise the real CLI offline, including exports, custody, and loopback serve."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PARSER = argparse.ArgumentParser()
TARGET = PARSER.add_mutually_exclusive_group()
TARGET.add_argument("--dll", default=str(ROOT / "src/Opscope/bin/Release/net8.0/opscope.dll"))
TARGET.add_argument("--executable", help="Test an extracted self-contained binary or installed tool shim.")
ARGS, _ = PARSER.parse_known_args()
DLL = Path(ARGS.dll).resolve()
DOTNET = os.environ.get("DOTNET_BIN", "dotnet")
EXECUTABLE = Path(ARGS.executable).resolve() if ARGS.executable else None
COMMAND = [str(EXECUTABLE)] if EXECUTABLE else [DOTNET, str(DLL)]


def fixture():
    return {
        "collectedAtUtc": "2026-10-25T12:00:00+00:00",
        "host": {"hostname": "cli-private-host", "osDescription": "Fixture OS", "platform": "linux", "architecture": "X64", "runtime": ".NET 8", "kernel": "fixture", "bootTimeUtc": "2026-10-25T10:00:00+00:00", "uptime": "02:00:00", "isElevated": False, "processorCount": 2, "currentUser": "cli-private-user"},
        "cpuUsedPercent": 12.5,
        "memory": {"totalBytes": 1000, "availableBytes": 600, "usedBytes": 400, "usedPercent": 40, "source": "fixture"},
        "disks": [], "network": [],
        "processes": [{"id": 42, "name": "worker", "user": "cli-private-user", "workingSetBytes": 1024, "workingSetMb": .001, "cpuTime": "00:00:12", "commandLine": "curl -u user:never-export-command-secret", "accessLimited": False}],
        "listeners": [{"protocol": "TCP", "localAddress": "10.20.30.40:443", "process": "worker pid=42", "source": "fixture"}],
        "services": [{"name": "worker", "state": "active/running", "source": "fixture"}],
        "security": {"firewalls": [], "firewallStatusKnown": False, "hasActiveFirewall": False, "exposedListeners": 0},
        "tooling": {"tools": []},
        "findings": [{"severity": 1, "code": "CLI_FIXTURE", "title": "<script>unsafe()</script>", "detail": "Authorization: Bearer never-export-header-secret", "recommendation": "Review evidence"}],
        "collectionWarnings": [], "collectionDuration": "00:00:00.0100000",
    }


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="opscope-cli-tests-")
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "snapshot.json"
        self.snapshot.write_text(json.dumps(fixture()), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def run_cli(self, *args, expected=0):
        result = subprocess.run([*COMMAND, *map(str, args)], cwd=self.root, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stderr.decode("utf-8", errors="replace"))
        return result.stdout

    def report(self, format_, path=None):
        return self.run_cli("report", self.snapshot, "--format", format_, "--fail-on", "none", *(["--out", path, "--quiet"] if path else []))

    def test_help_lists_new_commands(self):
        text = self.run_cli("--help").decode()
        for command in ["policy", "serve", "azure", "aws", "gcp", "kubernetes", "cloud catalog", "verify", "mcp", "notify"]:
            self.assertIn(command, text)

    def test_cloud_catalog_is_complete_local_and_readable_after_redaction(self):
        catalog = json.loads(self.run_cli("cloud", "catalog"))
        self.assertFalse(catalog["data"]["remoteRequestsMade"])
        providers = catalog["data"]["providers"]
        self.assertEqual({provider["providerId"] for provider in providers},
                         {"azure", "aws", "gcp", "oci", "digitalocean", "hetzner", "cloudflare", "openstack", "alibaba", "ibm", "scaleway", "kubernetes"})
        self.assertEqual(len(providers), 12)
        self.assertEqual([provider["providerId"] for provider in providers if provider["category"] == "cluster"], ["kubernetes"])
        self.assertEqual(len([provider for provider in providers if provider["category"] != "cluster"]), 11)
        for provider in providers:
            self.assertTrue(provider["capabilities"])
            self.assertTrue(all(isinstance(capability["operation"], str) for capability in provider["capabilities"]))
        gcp = json.loads(self.run_cli("cloud", "catalog", "--provider", "gcp"))
        self.assertEqual([provider["providerId"] for provider in gcp["data"]["providers"]], ["gcp"])
        self.assertTrue({"scc", "cost", "patches", "drift"}.issubset({capability["operation"] for capability in gcp["data"]["providers"][0]["capabilities"]}))
        for provider in providers:
            if provider["providerId"] in {"oci", "cloudflare", "openstack", "alibaba", "ibm", "scaleway"}:
                self.assertIn("metrics", {capability["operation"] for capability in provider["capabilities"]})
        self.assertFalse(catalog.get("warnings"))

    def test_new_configuration_reads_require_explicit_scopes_offline(self):
        scaleway = json.loads(self.run_cli("cloud", "catalog", "--provider", "scaleway"))
        self.assertIn("networks", {entry["operation"] for entry in scaleway["data"]["providers"][0]["capabilities"]})
        cases = [
            ("cloudflare", "posture", "--account", "a" * 32),
            ("cloudflare", "posture", "--account", "a" * 32, "--zones", "https://untrusted.invalid"),
            ("cloudflare", "posture", "--account", "a" * 32, "--zones", "b" * 32, "--cloudflare-checks", "unsupported"),
            ("alibaba", "posture"),
            ("alibaba", "posture", "--account", "123456", "--region", "eu-central-1", "--security-groups", "https://untrusted.invalid"),
            ("scaleway", "networks", "--project", "11111111-1111-1111-1111-111111111111", "--zone", "fr-par-1"),
            ("scaleway", "networks", "--project", "11111111-1111-1111-1111-111111111111", "--region", "https://untrusted.invalid")
        ]
        for args in cases:
            self.run_cli(*args, expected=2)

    def test_remote_hosting_rejects_invalid_setup_before_collection(self):
        history = self.root / "must-not-be-created.sqlite"
        cases = [
            ("--public-origin", "http://opscope.example.test"),
            ("--public-origin", "https://opscope.example.test"),
            ("--proxy-token-env", "OPSCOPE_TEST_MISSING_PROXY_SECRET"),
            ("--public-origin", "https://opscope.example.test", "--proxy-token-env", "OPSCOPE_TEST_MISSING_PROXY_SECRET"),
            ("--public-origin", "https://opscope.example.test", "--proxy-token-env", "invalid-variable-name"),
            ("--public-origin", "https://opscope.example.test/path", "--proxy-token-env", "OPSCOPE_TEST_MISSING_PROXY_SECRET"),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.run_cli("serve", "--history", history, *args, expected=2)
                self.assertFalse(history.exists(), "Invalid hosting setup must fail before collecting or saving host evidence")

    def test_digitalocean_project_capabilities_and_invalid_scopes_stay_offline(self):
        catalog = json.loads(self.run_cli("cloud", "catalog", "--provider", "digitalocean"))
        capabilities = catalog["data"]["providers"][0]["capabilities"]
        inventory = next(item for item in capabilities if item["operation"] == "inventory")
        self.assertEqual(set(inventory["resourceTypes"]), {"compute.vm", "storage.volume", "network.load-balancer", "network.vpc"})
        posture = next(item for item in capabilities if item["operation"] == "posture")
        self.assertEqual(set(posture["resourceTypes"]), {"compute.vm", "network.firewall"})
        for operation in ("inventory", "posture"):
            for args in [(), ("--project", "https://untrusted.invalid"), ("--project", "../project"),
                         ("--project", "11111111-1111-1111-1111-111111111111", "--endpoint", "https://untrusted.invalid")]:
                with self.subTest(operation=operation, args=args):
                    self.run_cli("digitalocean", operation, *args, expected=2)

    def test_ibm_networks_catalog_and_invalid_scopes_stay_offline(self):
        catalog = json.loads(self.run_cli("cloud", "catalog", "--provider", "ibm"))
        capabilities = catalog["data"]["providers"][0]["capabilities"]
        network = next(item for item in capabilities if item["operation"] == "networks")
        self.assertEqual(set(network["resourceTypes"]), {"network.vpc", "network.subnet", "network.securityGroup"})
        self.assertIn("inventory", {item["operation"] for item in capabilities})
        scope = ("--account", "a" * 32, "--resource-group", "b" * 32)
        for args in [
            (),
            ("--account", "https://untrusted.invalid", "--resource-group", "b" * 32, "--region", "us-south"),
            ("--account", "a" * 32, "--resource-group", "../group", "--region", "us-south"),
            (*scope, "--region", "https://untrusted.invalid"),
            (*scope, "--region", "us-south", "--endpoint", "https://untrusted.invalid"),
        ]:
            with self.subTest(args=args):
                self.run_cli("ibm", "networks", *args, expected=2)

    def test_drift_without_baseline_and_node_correlation_configuration_stay_offline(self):
        drift = json.loads(self.run_cli("gcp", "drift", "--project", "example-project", expected=2))
        self.assertEqual(drift["data"]["coverage"]["state"], "NotConfigured")
        for args in [
            ("kubernetes", "inventory", "--infrastructure-provider", "gcp"),
            ("kubernetes", "inventory", "--infrastructure-provider", "aws", "--kubernetes-nodes"),
            ("kubernetes", "inventory", "--infrastructure-provider", "gcp", "--kubernetes-nodes", "--projects", "invalid/path"),
            ("serve", "--cloud", "gcp", "--project", "example-project", "--infrastructure-provider", "gcp", "--kubernetes-nodes"),
            ("serve", "--cloud", "kubernetes", "--contexts", "reader", "--namespaces", "default", "--infrastructure-provider", "azure", "--kubernetes-nodes"),
            ("gcp", "inventory", "--project", "example-project", "--infrastructure-provider", "gcp", "--kubernetes-nodes"),
            ("gcp", "inventory", "--project", "example-project", "--profile", "unimplemented-selector")
        ]:
            self.run_cli(*args, expected=2)

    def test_cloud_configuration_rejects_unknown_unsupported_and_ambiguous_scopes(self):
        for args in [("cloud", "catalog", "--provider", "unknown"),
                     ("gcp", "metadata"),
                     ("gcp", "cost", "--project", "example-project"),
                     ("serve", "--cloud", "gcp"),
                     ("serve", "--cloud", "gcp,gcp", "--gcp-projects", "example-project"),
                     ("serve", "--cloud", "gcp", "--gcp-projects", "example-project,example-project"),
                     ("serve", "--cloud", "kubernetes"),
                     ("serve", "--cloud", "kubernetes", "--contexts", "reader"),
                     ("serve", "--cloud", "kubernetes", "--contexts", "reader", "--namespaces="),
                     ("serve", "--cloud", "kubernetes", "--contexts", "reader", "--namespaces", "default,default"),
                     ("serve", "--cloud", "kubernetes", "--contexts", "@untrusted", "--namespaces", "default"),
                     ("serve", "--cloud", "kubernetes", "--contexts", "reader,reader", "--namespaces", "default"),
                     ("kubernetes", "inventory", "--context", "reader", "--namespaces", "default,../../escape"),
                     ("kubernetes", "exec", "--context", "reader", "--namespaces", "default")]:
            with self.subTest(args=args):
                self.run_cli(*args, expected=2)

    def test_advanced_sources_require_explicit_configuration_without_fabricating_data(self):
        billing = json.loads(self.run_cli("gcp", "cost", "--project", "example-project", expected=2))
        self.assertFalse(billing["operationSucceeded"])
        self.assertNotIn("totalBill", json.dumps(billing))
        self.assertTrue(billing.get("warnings"))
        for provider, scope in [("ibm", ["--account", "testaccount", "--resource-group", "testgroup", "--region", "eu-de"]),
                                ("scaleway", ["--project", "11111111-1111-1111-1111-111111111111", "--zone", "fr-par-1"])]:
            with self.subTest(provider=provider):
                result = json.loads(self.run_cli(provider, "metrics", *scope, expected=2))
                self.assertFalse(result["operationSucceeded"])
                self.assertTrue(result.get("warnings"))
                self.assertFalse(result.get("data", {}).get("metrics", []), "Missing monitoring configuration must not produce synthetic zero metrics")

    def test_shared_extended_options_dispatch_without_format_or_policy(self):
        self.assertEqual(json.loads(self.run_cli("snapshot", "--input", self.snapshot, "--json", expected=1))["host"]["hostname"], "cli-private-host")
        output = self.root / "quiet-snapshot.json"
        self.assertEqual(self.run_cli("snapshot", "--input", self.snapshot, "--quiet", "--out", output, expected=1), b"")
        self.assertTrue(output.is_file())
        diff = json.loads(self.run_cli("diff", "--baseline", self.snapshot, "--input", self.snapshot, "--json"))
        self.assertEqual(diff["data"]["changes"], [])
        self.assertNotIn("Unknown option", self.run_cli("snapshot", "--input", self.root / "missing.json", expected=2).decode())

    def test_saved_evidence_never_silently_collects_another_host(self):
        for command in ["serve", "watch", "tui", "mcp", "environment", "history", "azure"]:
            with self.subTest(command=command):
                self.run_cli(command, "--input", self.snapshot, expected=2)
        for option in ["--cloud-context", "--no-processes", "--no-network", "--no-services"]:
            with self.subTest(option=option):
                self.run_cli("snapshot", "--input", self.snapshot, option, expected=2)
        self.run_cli("report", self.snapshot, "--evidence", "logs", expected=2)
        self.run_cli("diff", "--baseline", self.snapshot, "--input", self.snapshot, "--pack", ROOT / "examples/packs/base.yml", expected=2)

    def test_exports_preserve_contracts_and_redact(self):
        for format_ in ["json", "sarif", "junit", "html", "pdf", "csv", "jsonl", "cef"]:
            with self.subTest(format=format_):
                path = self.root / ("report." + format_)
                self.report(format_, path)
                content = path.read_bytes()
                self.assertGreater(len(content), 20)
                self.assertNotIn(b"never-export-command-secret", content)
                self.assertNotIn(b"never-export-header-secret", content)
                if format_ == "json": self.assertIn("findings", json.loads(content))
                if format_ == "sarif": self.assertEqual(json.loads(content)["version"], "2.1.0")
                if format_ == "junit": ET.fromstring(content)
                if format_ == "html":
                    self.assertNotIn(b"<script>unsafe()", content)
                    self.assertIn(b"&lt;script&gt;", content)
                if format_ == "pdf": self.assertTrue(content.startswith(b"%PDF-"))

    def test_asff_requires_and_uses_real_context(self):
        self.run_cli("report", self.snapshot, "--format", "asff", expected=2)
        value = json.loads(self.run_cli("report", self.snapshot, "--format", "asff", "--account", "123456789012", "--region", "eu-west-1", "--fail-on", "none"))
        self.assertEqual(value["Findings"][0]["AwsAccountId"], "123456789012")

    def test_failure_threshold_and_full_opt_in(self):
        self.run_cli("report", self.snapshot, "--format", "json", "--fail-on", "warning", expected=1)
        self.run_cli("report", self.snapshot, "--format", "json", "--fail-on", "critical")
        safe = self.report("json")
        self.assertNotIn(b"cli-private-host", safe)
        full = self.run_cli("report", self.snapshot, "--format", "json", "--full", "--fail-on", "none")
        self.assertIn(b"cli-private-host", full)

    def test_policy_pack_and_declarative_plugin_validation(self):
        self.run_cli("policy", "validate", ROOT / "examples/policies/opscope.yml")
        self.run_cli("pack", "validate", ROOT / "examples/packs/ssh-comprometido.yml")
        self.run_cli("plugins", "validate", ROOT / "examples/policies/plugin-exposure.yml")
        bad = self.root / "bad.yml"
        bad.write_text("version: 1\nexecute: rm\n", encoding="utf-8")
        self.run_cli("policy", "validate", bad, expected=2)

    def test_ioc_timeline_fleet_and_triage_are_real_cli_routes(self):
        iocs = self.root / "iocs.csv"
        iocs.write_text("type,value\nip,10.20.30.40\n", encoding="utf-8")
        result = json.loads(self.run_cli("ioc", iocs, "--input", self.snapshot, "--fail-on", "none"))
        self.assertGreater(len(result["findings"]), 0)
        before = fixture(); before["collectedAtUtc"] = "2026-10-25T11:00:00+00:00"
        baseline = self.root / "baseline.json"; baseline.write_text(json.dumps(before), encoding="utf-8")
        csv = self.run_cli("timeline", baseline, "--input", self.snapshot, "--format", "csv")
        self.assertIn(b"timestampUtc,kind,source,description", csv)
        other = copy.deepcopy(before); other["host"]["hostname"] = "other-private-host"
        second = self.root / "second.json"; second.write_text(json.dumps(other), encoding="utf-8")
        fleet = json.loads(self.run_cli("fleet", self.snapshot, second, "--fail-on", "none"))
        self.assertEqual(len(fleet["data"]["hosts"]), 2)
        triage = json.loads(self.run_cli("triage", "--input", self.snapshot, "--scenario", "port-exposed", "--fail-on", "none"))
        self.assertGreater(len(triage["data"]["steps"]), 0)

    def test_custody_bundle_verification_tamper_and_handoff_hash(self):
        bundle = self.root / "bundle.zip"
        self.run_cli("bundle", "--input", self.snapshot, "--out", bundle, "--fail-on", "none", "--quiet")
        self.assertEqual(Path(str(bundle) + ".sha256").read_text().strip(), hashlib.sha256(bundle.read_bytes()).hexdigest())
        verified = json.loads(self.run_cli("verify", bundle))
        self.assertTrue(verified["isValid"])
        with zipfile.ZipFile(bundle) as archive:
            self.assertIn("manifest.json", archive.namelist())
            self.assertNotIn(b"never-export-command-secret", archive.read("snapshot.json"))
        report = json.loads(self.run_cli("report", self.snapshot, "--bundle", bundle, "--format", "json", "--fail-on", "none"))
        self.assertIn(hashlib.sha256(bundle.read_bytes()).hexdigest().encode(), json.dumps(report).encode())
        content = bytearray(bundle.read_bytes()); content[-1] ^= 1; bundle.write_bytes(content)
        self.assertFalse(json.loads(self.run_cli("verify", bundle, expected=1))["isValid"])

    def test_notification_preview_never_sends_and_invalid_endpoint_fails(self):
        preview = json.loads(self.run_cli("notify", "--input", self.snapshot, "--target", "slack"))
        self.assertFalse(preview["sent"])
        self.assertNotIn("never-export-header-secret", json.dumps(preview))
        rejected = json.loads(self.run_cli("notify", "--input", self.snapshot, "--target", "slack", "--endpoint", "http://127.0.0.1/", "--confirm-send", expected=2))
        self.assertFalse(rejected["sent"])

    def test_private_history_is_available_from_cli(self):
        path = self.root / "history.sqlite"
        report = json.loads(self.run_cli("history", "list", "--history", path))
        self.assertEqual(report["data"], [])
        self.assertTrue(path.is_file())

    def test_snapshot_policy_json_remains_a_usable_flat_baseline(self):
        path = self.root / "policy-baseline.json"
        self.run_cli("snapshot", "--input", self.snapshot, "--policy", ROOT / "examples/policies/opscope.yml", "--json", "--redact", "--out", path, "--quiet", "--fail-on", "none")
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("host", saved)
        self.assertEqual(saved["host"]["hostname"], "[redacted-host]")
        self.assertNotIn("data", saved)
        self.run_cli("report", path, "--format", "json", "--quiet", "--fail-on", "none")

    def test_saved_extra_reports_and_strict_coverage(self):
        data = fixture()
        data["reports"] = {"evidence": {"kind": "evidence", "collectedAtUtc": data["collectedAtUtc"], "findings": [], "data": {"message": "token=never-export-attached"}, "warnings": []}}
        data["collectionWarnings"] = ["Fixture collection was incomplete"]
        self.snapshot.write_text(json.dumps(data), encoding="utf-8")
        output = self.report("json")
        self.assertNotIn(b"never-export-attached", output)
        self.run_cli("report", self.snapshot, "--format", "json", "--fail-on", "none", "--require-complete", expected=2)
        for format_ in ["json", "csv"]:
            self.run_cli("timeline", "--input", self.snapshot, "--format", format_, "--require-complete", "--quiet", expected=2)
        self.run_cli("notify", "--input", self.snapshot, "--target", "unknown", expected=2)

    def test_tui_can_render_a_bounded_read_only_sample(self):
        output = self.run_cli("tui", "--page", "services", "--samples", "1", "--no-network", "--no-processes", "--no-services")
        self.assertIn(b"opscope TUI | services", output)

    def test_real_serve_uses_loopback_auth_and_clean_shutdown(self):
        process = subprocess.Popen([*COMMAND, "serve", "--history", str(self.root / "server.sqlite"), "--no-network", "--no-processes", "--no-services"], cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 20
            bootstrap = None
            while time.monotonic() < deadline:
                line = process.stdout.readline()
                match = re.search(r"http://127\.0\.0\.1:\d+/#token=([A-F0-9]+)", line)
                if match: bootstrap = match; break
                if process.poll() is not None: self.fail("serve exited before becoming ready")
            self.assertIsNotNone(bootstrap, "No loopback bootstrap URL")
            origin = bootstrap.group(0).split("/#")[0]
            try: urllib.request.urlopen(origin + "/api/snapshot", timeout=3); self.fail("Unauthenticated snapshot accepted")
            except urllib.error.HTTPError as error: self.assertIn(error.code, [401, 403])
            request = urllib.request.Request(origin + "/api/snapshot", headers={"X-Opscope-Token": bootstrap.group(1)})
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(json.load(response)["host"]["hostname"], "[redacted-host]")
            if os.name != "nt":
                process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
                self.assertEqual(process.returncode, 0)
        finally:
            if process.poll() is None: process.terminate()
            try: process.communicate(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.communicate()


if __name__ == "__main__":
    if not (EXECUTABLE or DLL).is_file(): raise SystemExit("Build the Release CLI or supply an existing --executable before running these tests.")
    unittest.main(argv=[__file__], verbosity=2)
