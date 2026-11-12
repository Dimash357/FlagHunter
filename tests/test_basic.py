import unittest
from pathlib import Path
from flaghunter.analyzer import Analyzer
from flaghunter.rules import PatternEngine

class SmokeTests(unittest.TestCase):
    def test_rules_load(self):
        self.assertGreaterEqual(len(PatternEngine().rules),10)
    def test_file_scan(self):
        result=Analyzer().scan_path(Path("examples"))
        self.assertGreaterEqual(len(result.scanned),2)
        cats={x.category for x in result.findings}
        self.assertIn("XSS",cats)
        self.assertIn("FILE_UPLOAD",cats)
        self.assertIn("FLAG",cats)
    def test_no_real_secret_in_flag_evidence(self):
        findings=PatternEngine().scan("test","CTF{very_private_flag}")
        self.assertTrue(findings)
        self.assertNotIn("very_private_flag",str([f.evidence for f in findings]))

if __name__=="__main__":unittest.main()
