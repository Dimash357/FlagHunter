"""End-to-end tests against a local vulnerable fixture app."""

import asyncio
import unittest

from flaghunter.service import scan
from flaghunter.models import CATEGORIES

from tests.fixture_app import FixtureServer


def run(coro):
    return asyncio.run(coro)


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FixtureServer().__enter__()
        cls.base = cls.server.base

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__()

    def _scan(self, **kw):
        defaults = dict(
            url=self.base, authorized=True, allow_private=True,
            out="output/test", max_pages=20, max_depth=2,
        )
        defaults.update(kw)
        return run(scan(**defaults))

    def test_passive_crawl_discovers_surface(self):
        result, _ = self._scan()
        # Forms + query endpoints discovered.
        urls = {e.url for e in result.endpoints}
        self.assertTrue(any("/search" in u for u in urls))
        self.assertTrue(any("/upload" in u or "/login" in u for u in urls))
        # Cookies captured with privilege hint.
        names = {c.name for c in result.cookies}
        self.assertIn("role", names)
        self.assertTrue(any(c.looks_privilege for c in result.cookies))

    def test_structural_and_signature_findings(self):
        result, _ = self._scan()
        cats = {f.category for f in result.findings}
        # Admin route reachable → broken access control.
        self.assertIn("BROKEN_ACCESS_CONTROL", cats)
        # File upload form.
        self.assertIn("FILE_UPLOAD", cats)
        # SSRF-looking param (url=) from the JS fetch.
        self.assertIn("SSRF", cats)

    def test_flag_hint_from_comment_and_robots(self):
        result, _ = self._scan()
        kinds = {h.kind for h in result.flag_hints}
        self.assertTrue({"comment", "path"} & kinds)

    def test_active_probes_find_reflection_and_sqli_and_ssti(self):
        result, _ = self._scan(active=True)
        evid = {(f.category, f.status) for f in result.findings if f.status == "evidence"}
        cats_with_evidence = {c for c, s in evid}
        # Reflected XSS on /search, error-based SQLi on /item, SSTI on /render.
        self.assertIn("XSS", cats_with_evidence)
        self.assertIn("SQLI", cats_with_evidence)
        self.assertIn("SSTI", cats_with_evidence)

    def test_every_vuln_finding_has_a_playbook(self):
        result, _ = self._scan(active=True)
        for f in result.findings:
            if f.category in CATEGORIES:
                self.assertTrue(f.verification, f"{f.category} missing steps")
                self.assertTrue(f.commands, f"{f.category} missing commands")
                self.assertTrue(f.expected, f"{f.category} missing expected")

    def test_report_files_written(self):
        result, report = self._scan()
        self.assertTrue(report.exists())
        self.assertTrue((report.parent / "report.json").exists())
        html = report.read_text(encoding="utf-8")
        self.assertIn("FlagHunter", html)
        self.assertIn("renderResult", html)

    def test_scope_blocks_platform_host(self):
        # A redirect or link to another host must never be fetched.
        result, _ = self._scan()
        for u in result.scanned:
            self.assertIn("127.0.0.1", u)

    def test_authorization_required(self):
        with self.assertRaises(ValueError):
            run(scan(url=self.base, authorized=False, allow_private=True, out="output/test"))


if __name__ == "__main__":
    unittest.main()
