#!/usr/bin/env python3
"""
Unit tests for smart-tunnel CLI Controller.
"""

import unittest
import tempfile
import os
import sys
import json
import socket
import shutil
from pathlib import Path
import subprocess

BIN_PATH = Path(__file__).resolve().parent.parent.parent / "bin" / "smart-tunnel"

class TestSmartTunnelCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temp_dir.name)
        self.blocked_json = self.config_dir / "blocked.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_cli(self, args):
        cmd = [sys.executable, str(BIN_PATH), "--config-dir", str(self.config_dir)] + args
        env = dict(os.environ)
        env["SMART_TUNNEL_CONFIG_DIR"] = str(self.config_dir)
        return subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_help(self):
        res = self.run_cli(["--help"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("smart-tunnel", res.stdout)

    def test_status_stopped(self):
        res = self.run_cli(["status"])
        self.assertEqual(res.returncode, 2)
        self.assertIn("SSH Tunnel:", res.stdout)
        self.assertIn("Smart Proxy:", res.stdout)

    def test_domain_management(self):
        # Block
        res = self.run_cli(["block", "testsite.com"])
        self.assertEqual(res.returncode, 0)
        self.assertTrue(self.blocked_json.is_file())

        with open(self.blocked_json) as f:
            data = json.load(f)
        self.assertIn("testsite.com", data.get("blocked_domains", {}))

        # List
        res = self.run_cli(["list"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("testsite.com", res.stdout)

        # Unblock
        res = self.run_cli(["unblock", "testsite.com"])
        self.assertEqual(res.returncode, 0)

        with open(self.blocked_json) as f:
            data = json.load(f)
        self.assertNotIn("testsite.com", data.get("blocked_domains", {}))

    def test_invalid_domain(self):
        res = self.run_cli(["block", "..invalid.."])
        self.assertNotEqual(res.returncode, 0)

    def test_log_empty(self):
        res = self.run_cli(["log"])
        self.assertEqual(res.returncode, 0)

    def test_install(self):
        prefix = self.config_dir / "local"
        res = self.run_cli(["install", "--prefix", str(prefix)])
        self.assertEqual(res.returncode, 0)
        self.assertTrue((prefix / "bin" / "smart-tunnel").exists())

    def test_test_offline(self):
        # Hermetic: bind to ports that are guaranteed free so the test does
        # not depend on whether the host is running real services on 8080/1088.
        s1, s2 = socket.socket(), socket.socket()
        s1.bind(("127.0.0.1", 0)); s2.bind(("127.0.0.1", 0))
        free_proxy, free_socks = s1.getsockname()[1], s2.getsockname()[1]
        s1.close(); s2.close()
        res = self.run_cli(["--proxy-port", str(free_proxy),
                            "--socks-port", str(free_socks),
                            "test", "example.com"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("OFFLINE", res.stdout)

if __name__ == "__main__":
    unittest.main()
