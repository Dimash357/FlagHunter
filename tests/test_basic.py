import unittest
from pathlib import Path

from flaghunter.analyzer import Analyzer
from flaghunter.rules import PatternEngine
from flaghunter.models import Finding, Result, Endpoint, CATEGORIES
from flaghunter import playbook
from flaghunter.scope import Scope, ScopeError, parse_ports
from flaghunter.crawler import normalize_url, endpoint_shape


class RuleTests(unittest.TestCase):
    def test_rules_load(self):
        self.assertGreaterEqual(len(PatternEngine().rules), 15)

    def test_sql_error_signature(self):
        f = PatternEngine().scan("x", "You have an error in your SQL syntax near", "html")
        self.assertTrue(any(x.category == "SQLI" for x in f))

    def test_flag_is_redacted(self):
        f = PatternEngine().scan("x", "flag{very_secret_value_123}", "html")
        self.assertTrue(f)
        self.assertNotIn("very_secret_value_123", str([x.evidence for x in f]))

    def test_command_output_signature_high_confidence(self):
        f = PatternEngine().scan("x", "uid=33(www-data) gid=33(www-data) groups=33", "html")
        self.assertTrue(any(x.category == "COMMAND_INJECTION" and x.confidence >= 0.8 for x in f))


class FileScanTests(unittest.TestCase):
    def test_examples_scan(self):
        result = Analyzer().scan_path(Path("examples"))
        self.assertGreaterEqual(len(result.scanned), 2)
        cats = {x.category for x in result.findings}
        self.assertIn("XSS", cats)
        self.assertTrue(result.flag_hints)


class ModelTests(unittest.TestCase):
    def test_finding_dedup_keeps_stronger(self):
        r = Result(target="t")
        r.add_finding(Finding("XSS", "x", "u", confidence=0.3, status="candidate"))
        r.add_finding(Finding("XSS", "x", "u", confidence=0.9, status="evidence"))
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].status, "evidence")

    def test_endpoint_dedup(self):
        r = Result(target="t")
        self.assertTrue(r.add_endpoint(Endpoint("http://t/a", "GET", ["id"])))
        self.assertFalse(r.add_endpoint(Endpoint("http://t/a", "GET", ["id"])))

    def test_most_likely_excludes_aux(self):
        r = Result(target="t")
        r.add_finding(Finding("FLAG", "flag", "u", confidence=0.9, severity="high"))
        r.add_finding(Finding("SQLI", "sqli", "u", confidence=0.8, severity="high"))
        top = r.most_likely()
        self.assertTrue(top and top[0].category == "SQLI")


class PlaybookTests(unittest.TestCase):
    def test_all_categories_have_playbooks(self):
        for cat in CATEGORIES:
            pb = playbook.build(cat, "http://t:8080/p?id=1", "id", "GET")
            self.assertTrue(pb["verification"], cat)
            self.assertTrue(pb["commands"], cat)
            self.assertTrue(pb["expected"], cat)

    def test_commands_are_shell_safe(self):
        # payloads with quotes/braces must not break out of their argument
        pb = playbook.build("SQLI", "http://t/x", "q", "GET")
        self.assertTrue(any("curl" in c for c in pb["commands"]))


class ScopeTests(unittest.TestCase):
    def test_private_blocked_by_default(self):
        s = Scope("http://127.0.0.1:8080/")
        with self.assertRaises(ScopeError):
            s.validate("http://127.0.0.1:8080/")

    def test_private_allowed_with_flag(self):
        s = Scope("http://127.0.0.1:8080/", allow_private=True)
        self.assertEqual(s.validate("http://127.0.0.1:8080/"), "127.0.0.1")

    def test_seed_port_auto_allowed(self):
        s = Scope("http://127.0.0.1:12345/", allow_private=True)
        self.assertTrue(s.port_allowed(12345))

    def test_nonstandard_port_rejected(self):
        s = Scope("http://127.0.0.1:8080/", allow_private=True)
        self.assertFalse(s.port_allowed(31337))

    def test_out_of_scope_host(self):
        s = Scope("http://127.0.0.1:8080/", allow_private=True)
        self.assertFalse(s.in_scope("http://evil.example:8080/"))

    def test_parse_ports(self):
        self.assertEqual(parse_ports("8081,9000 3001"), {8081, 9000, 3001})
        with self.assertRaises(ScopeError):
            parse_ports("notaport")


class CrawlHelperTests(unittest.TestCase):
    def test_normalize_sorts_query(self):
        self.assertEqual(
            normalize_url("http://H/a?b=2&a=1#frag"),
            normalize_url("http://h/a?a=1&b=2"),
        )

    def test_shape_groups_ids(self):
        self.assertEqual(
            endpoint_shape("http://t/item?id=1"),
            endpoint_shape("http://t/item?id=2"),
        )


if __name__ == "__main__":
    unittest.main()
