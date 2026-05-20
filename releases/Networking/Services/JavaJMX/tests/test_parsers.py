"""
Tests for beanshooter_batch parsers.

Run:
    python -m unittest tests/test_parsers.py
    # or
    python tests/test_parsers.py
"""
import sys
import unittest
from pathlib import Path

# Make beanshooter_batch importable when tests are invoked from any cwd.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from beanshooter_batch import (  # noqa: E402
    HostResult,
    clean_line,
    parse_brute_hits,
    parse_enum_findings,
    parse_enum_sections,
    parse_list_mbeans,
    _redact_args,
    _redact_text,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
class TestCleanLine(unittest.TestCase):
    def test_strips_plus_marker(self):
        self.assertEqual(clean_line("[+] hello"), "hello")

    def test_strips_minus_marker(self):
        self.assertEqual(clean_line("[-] hello"), "hello")

    def test_strips_bang_marker(self):
        self.assertEqual(clean_line("[!] hello"), "hello")

    def test_strips_star_marker(self):
        self.assertEqual(clean_line("[*] hello"), "hello")

    def test_strips_marker_and_indent(self):
        self.assertEqual(clean_line("[+] \tfoo"), "foo")

    def test_no_marker_kept(self):
        self.assertEqual(clean_line("plain text"), "plain text")

    def test_does_not_strip_bare_plus_prefix(self):
        # Regression: old lstrip("[+-!] ") would mangle these.
        self.assertEqual(clean_line("+java"), "+java")
        self.assertEqual(clean_line("--username"), "--username")

    def test_strips_ansi(self):
        self.assertEqual(clean_line("\x1b[32m[+] green\x1b[0m"), "green")


# --------------------------------------------------------------------------- #
class TestSectionParser(unittest.TestCase):
    def test_sections_keyed_by_name(self):
        text = (FIXTURES / "enum_anonymous_vulnerable.txt").read_text()
        sections = parse_enum_sections(text)
        self.assertIn("for unauthorized access", sections)
        self.assertIn("pre-auth deserialization behavior", sections)
        self.assertIn("available mbeans", sections)
        self.assertIn("available bound names", sections)

    def test_empty_input_returns_empty(self):
        self.assertEqual(parse_enum_sections(""), {})

    def test_non_enum_output_returns_empty(self):
        self.assertEqual(
            parse_enum_sections("connection refused\n"), {}
        )


# --------------------------------------------------------------------------- #
class TestEnumFindings(unittest.TestCase):

    def _parse(self, fixture: str) -> HostResult:
        text = (FIXTURES / fixture).read_text()
        r = HostResult(host="t", port=1)
        parse_enum_findings(text, r)
        return r

    # --- the bugs from the review ----------------------------------------- #
    def test_anonymous_access_detected_on_real_output(self):
        """REGRESSION: original parser missed 'does not require
        authentication' and therefore never fired the anonymous finding."""
        r = self._parse("enum_anonymous_vulnerable.txt")
        self.assertTrue(r.anonymous_access)
        self.assertFalse(r.auth_required)
        self.assertTrue(any(
            f.category == "anonymous" and "anonymous" in f.title.lower()
            for f in r.findings
        ))

    def test_preauth_deser_detected_on_real_output(self):
        """REGRESSION: original parser required 'vulnerable'/'exploitable'
        near 'deserializ', but real output uses 'accepted the payload class'
        + 'Configuration Status: Non Default'."""
        r = self._parse("enum_authrequired_preauth_deser.txt")
        self.assertTrue(any(
            f.category == "rce" and "deserialization" in f.title.lower()
            for f in r.findings
        ))

    def test_auth_required_does_not_false_positive_anon(self):
        r = self._parse("enum_authrequired_preauth_deser.txt")
        self.assertFalse(r.anonymous_access)
        self.assertTrue(r.auth_required)

    def test_hardened_endpoint_has_no_critical(self):
        r = self._parse("enum_authrequired_nonvuln.txt")
        self.assertFalse(r.anonymous_access)
        self.assertTrue(r.auth_required)
        self.assertFalse(any(f.severity == "critical" for f in r.findings))

    def test_jmxmp_no_sasl_flagged(self):
        r = self._parse("enum_jmxmp_no_sasl.txt")
        self.assertTrue(r.anonymous_access)
        self.assertTrue(any(
            "jmxmp" in f.title.lower() for f in r.findings
        ))

    def test_mbean_count_extracted(self):
        r = self._parse("enum_anonymous_vulnerable.txt")
        self.assertEqual(r.mbean_count, 198)
        self.assertEqual(r.nondefault_mbean_count, 5)

    def test_bound_names_extracted(self):
        r = self._parse("enum_anonymous_vulnerable.txt")
        self.assertIn("jmxrmi", r.bound_names)

    # --- guards against negation false positives -------------------------- #
    def test_negation_does_not_flip_anon(self):
        """Synthetic guard: 'does not require authentication' must not be
        misread because of the trailing word 'authentication'."""
        synthetic = (
            "[+] Checking for unauthorized access:\n"
            "[+] \t- Remote MBean server does not require authentication.\n"
            "[+] \tVulnerability Status: Vulnerable\n"
        )
        r = HostResult(host="t", port=1)
        parse_enum_findings(synthetic, r)
        self.assertTrue(r.anonymous_access)

    def test_negation_does_not_flip_auth_required(self):
        synthetic = (
            "[+] Checking for unauthorized access:\n"
            "[+] \t- Remote MBean server requires authentication.\n"
            "[+] \tVulnerability Status: Non Vulnerable\n"
        )
        r = HostResult(host="t", port=1)
        parse_enum_findings(synthetic, r)
        self.assertFalse(r.anonymous_access)
        self.assertTrue(r.auth_required)

    def test_rejected_payload_does_not_fire_deser(self):
        synthetic = (
            "[+] Checking pre-auth deserialization behavior:\n"
            "[+] \t- Remote MBeanServer rejected the payload class.\n"
            "[+] \tVulnerability Status: Non Vulnerable\n"
        )
        r = HostResult(host="t", port=1)
        parse_enum_findings(synthetic, r)
        self.assertFalse(any(
            "deserialization" in f.title.lower() for f in r.findings
        ))


# --------------------------------------------------------------------------- #
class TestBruteParser(unittest.TestCase):
    def test_hits_extracted(self):
        text = (FIXTURES / "brute_with_hits.txt").read_text()
        hits = parse_brute_hits(text)
        self.assertIn(("admin", "admin"), hits)
        self.assertIn(("tomcat", "tomcat"), hits)

    def test_no_hits(self):
        self.assertEqual(
            parse_brute_hits("[+] Bruteforce finished. 0 found.\n"), []
        )


# --------------------------------------------------------------------------- #
class TestListMBeansParser(unittest.TestCase):
    def test_common_mbeans_extracted(self):
        text = (FIXTURES / "list_mbeans.txt").read_text()
        mbeans = parse_list_mbeans(text)
        self.assertIn("java.lang:type=Memory", mbeans)
        self.assertIn("javax.management.loading:type=MLet", mbeans)

    def test_quoted_values_accepted(self):
        """REGRESSION: original ObjectName regex rejected names containing
        forward slashes inside quoted values (e.g. JNDI paths)."""
        text = (FIXTURES / "list_mbeans.txt").read_text()
        mbeans = parse_list_mbeans(text)
        self.assertTrue(any('jdbc/foo' in m for m in mbeans))

    def test_dedup(self):
        text = (
            "[+] \tjava.lang:type=Memory\n"
            "[+] \tjava.lang:type=Memory\n"
        )
        self.assertEqual(parse_list_mbeans(text), ["java.lang:type=Memory"])


# --------------------------------------------------------------------------- #
class TestRedaction(unittest.TestCase):
    def test_password_value_redacted(self):
        args = ["docker", "run", "image", "--username", "admin",
                "--password", "hunter2", "enum", "host", "9010"]
        out = _redact_args(args)
        self.assertNotIn("hunter2", out)
        self.assertIn("***", out)
        # username left alone
        self.assertIn("admin", out)

    def test_text_redaction(self):
        out = _redact_text("login=hunter2 OK", ["hunter2"])
        self.assertEqual(out, "login=*** OK")

    def test_empty_secret_noop(self):
        self.assertEqual(_redact_text("foo", [""]), "foo")
        self.assertEqual(_redact_text("foo", []), "foo")


if __name__ == "__main__":
    unittest.main(verbosity=2)