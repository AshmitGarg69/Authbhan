#!/usr/bin/env python3
"""
Adversarial Test Harness 3: Fortinet DER Detection Fuzzing
Tests:
- Serial number prefix variations (FG6H, fg6h, mixed case, trailing nulls)
- Email address casing (support@fortinet.com, SUPPORT@FORTINET.COM, Support@Fortinet.com)
- Organization variations (Fortinet, FORTINET, fortinet, Fortinet Inc)
- Legitimate fortinet.com domains vs malicious lookalikes
- Host with port edge cases ("fortinet.com:443")
- Legitimate fortinet appliance certs bearing serial number or support email on fortinet.com
"""

import importlib.util
import unittest
from pathlib import Path

# Load smart-proxy.py
SRC_PATH = Path("/home/ashmit/Code/smart-tunnel/src/smart-proxy.py")
spec = importlib.util.spec_from_file_location("smart_proxy", str(SRC_PATH))
proxy_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_mod)

is_fortinet_cert = proxy_mod.is_fortinet_cert


class TestAdversarialFortinetDetection(unittest.TestCase):

    def test_case_sensitivity_on_fg6h(self):
        """Test variations of FortiGate hardware serial numbers."""
        variations = [
            (b"MIIB\x00CN=FG6H0FTB22905105\x00", "FG6H uppercase"),
            (b"MIIB\x00CN=fg6h0ftb22905105\x00", "fg6h lowercase"),
            (b"MIIB\x00CN=Fg6H0FTB22905105\x00", "Fg6H mixed case"),
            (b"MIIB\x00CN=FG6H\x00", "FG6H short with trailing null"),
            (b"\x00\x00FG6H0FTB22905105\x00\x00", "FG6H surrounded by nulls"),
        ]
        print("\n--- FG6H Serial Number Fuzzing ---")
        for der_bytes, desc in variations:
            res = is_fortinet_cert(der_bytes, "store.steampowered.com")
            print(f"[EMPIRICAL] {desc}: is_fortinet_cert -> {res}")

    def test_case_sensitivity_on_support_email(self):
        """Test variations of default contact email."""
        variations = [
            (b"emailAddress=support@fortinet.com", "exact lowercase"),
            (b"emailAddress=SUPPORT@FORTINET.COM", "ALL UPPERCASE"),
            (b"emailAddress=Support@Fortinet.com", "CamelCase"),
            (b"emailAddress=Support@fortinet.com\x00", "Mixed with trailing null"),
        ]
        print("\n--- Support Email Fuzzing ---")
        for der_bytes, desc in variations:
            res = is_fortinet_cert(der_bytes, "store.steampowered.com")
            print(f"[EMPIRICAL] {desc}: is_fortinet_cert -> {res}")

    def test_case_sensitivity_on_organization(self):
        """Test variations of Fortinet organization name in DER cert."""
        variations = [
            (b"O=Fortinet\x00", "Fortinet TitleCase"),
            (b"O=FORTINET\x00", "FORTINET ALL CAPS"),
            (b"O=fortinet\x00", "fortinet all lowercase"),
            (b"O=Fortinet Inc\x00", "Fortinet Inc"),
            (b"O=FORTINET TECHNOLOGIES INC\x00", "FORTINET TECHNOLOGIES INC"),
        ]
        print("\n--- Organization Name Fuzzing ---")
        for der_bytes, desc in variations:
            res = is_fortinet_cert(der_bytes, "store.steampowered.com")
            print(f"[EMPIRICAL] {desc}: is_fortinet_cert -> {res}")

    def test_legitimate_fortinet_domains(self):
        """Legitimate fortinet.com domains should NOT be flagged as MITM."""
        der_org = b"MIIB\x00O=Fortinet\x00CN=fortinet.com"
        legit_hosts = [
            "fortinet.com",
            "www.fortinet.com",
            "docs.fortinet.com",
            "support.fortinet.com",
            "api.fortinet.com.",
            "FORTINET.COM",
            "docs.FORTINET.COM",
        ]
        print("\n--- Legitimate Fortinet Domains ---")
        for host in legit_hosts:
            res = is_fortinet_cert(der_org, host)
            print(f"[EMPIRICAL] Legit host '{host}': is_fortinet_cert -> {res}")
            self.assertFalse(res, f"Legitimate Fortinet host {host} was flagged as MITM!")

    def test_legitimate_fortinet_domains_with_port(self):
        """Check what happens if host has port: 'fortinet.com:443'."""
        der_org = b"MIIB\x00O=Fortinet\x00CN=fortinet.com"
        res = is_fortinet_cert(der_org, "fortinet.com:443")
        print(f"\n[EMPIRICAL] Legit host with port 'fortinet.com:443': is_fortinet_cert -> {res}")

    def test_legitimate_fortinet_appliance_cert_with_serial_or_email(self):
        """
        Check if a real Fortinet appliance on fortinet.com having FG6H or support email
        is erroneously flagged as MITM.
        """
        der_serial = b"O=Fortinet\x00CN=fg.fortinet.com\x00serial=FG6H0FTB22905105"
        der_email = b"O=Fortinet\x00CN=support.fortinet.com\x00email=support@fortinet.com"

        res_serial = is_fortinet_cert(der_serial, "fortinet.com")
        res_email = is_fortinet_cert(der_email, "support.fortinet.com")
        print(f"\n[EMPIRICAL] fortinet.com with FG6H serial: is_fortinet_cert -> {res_serial}")
        print(f"[EMPIRICAL] support.fortinet.com with support email: is_fortinet_cert -> {res_email}")

    def test_malicious_fortinet_lookalike_domains(self):
        """Malicious lookalike domains presenting Fortinet cert MUST be flagged as MITM."""
        der_org = b"MIIB\x00O=Fortinet\x00CN=intercepted"
        fake_hosts = [
            "fake-fortinet.com",
            "notfortinet.com",
            "evilfortinet.com",
            "fortinet.com.attacker.com",
            "fortinet.com.evil.org",
        ]
        print("\n--- Malicious Lookalike Domains ---")
        for host in fake_hosts:
            res = is_fortinet_cert(der_org, host)
            print(f"[EMPIRICAL] Lookalike host '{host}': is_fortinet_cert -> {res}")
            self.assertTrue(res, f"Lookalike host {host} should be flagged as MITM!")


if __name__ == "__main__":
    unittest.main()
