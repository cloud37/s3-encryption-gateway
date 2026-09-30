#!/usr/bin/env python3
"""Regression tests for inventory directive parsing (no third-party packages)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("gosec-suppressions.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class DirectiveTests(unittest.TestCase):
    def test_rejects_malformed_directives(self):
        for comment in [
            "// #nosec G115 --   ",
            "// #nosec -- missing rule; #nosec G115 -- valid reason",
            "// #nosec G115 G115 -- duplicate",
            "// #nosec G115 -- reason; #nosec G402 -- duplicate directive",
            "// #nosec G115",
        ]:
            with self.subTest(comment=comment), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "sample.go").write_text("package sample\n"+comment+"\n")
                with self.assertRaises(ValueError):
                    inventory.inventory(root)

    def test_valid_comments_and_quoted_literals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sample.go").write_text('package sample\nvar s="// #nosec G115"\n// #nosec G115 -- bounded by an explicit check\n')
            result = inventory.inventory(root)
            self.assertIn("sample.go:3", result)
            self.assertNotIn("sample.go:2", result)


if __name__ == "__main__":
    unittest.main()
