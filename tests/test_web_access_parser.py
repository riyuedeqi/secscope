#!/usr/bin/env python3
from __future__ import print_function

import os
import tempfile
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "helpers"))

import web_access_parser


class WebAccessParserTests(unittest.TestCase):
    def test_combined_log(self):
        row = web_access_parser.parse_line(
            '192.0.2.10 - - [05/Aug/2026:12:00:00 +0800] "POST /img/a.jpg?cmd=id HTTP/1.1" 200 42 "-" "curl/8"',
            "auto",
        )
        self.assertEqual(row["remote_ip"], "192.0.2.10")
        self.assertEqual(row["method"], "POST")
        self.assertEqual(row["status"], "200")
        self.assertEqual(row["parse_status"], "FULL_PARSE")

    def test_json_log(self):
        row = web_access_parser.parse_line(
            '{"client_ip":"198.51.100.4","timestamp":1770000000,"request":"GET /x.php HTTP/1.1","status_code":404,"http_user_agent":"agent"}',
            "auto",
        )
        self.assertEqual(row["uri"], "/x.php")
        self.assertEqual(row["status"], 404)
        self.assertEqual(row["parse_status"], "FULL_PARSE")

    def test_unparsed_line_is_preserved_as_partial(self):
        row = web_access_parser.parse_line("not an access log", "auto")
        self.assertEqual(row["parse_status"], "PARTIAL_PARSE")

    def test_cli_keeps_partial_row_and_hash(self):
        with tempfile.TemporaryDirectory(prefix="secscope-web-log-") as temp:
            source = os.path.join(temp, "input.tsv")
            output = os.path.join(temp, "normalized.tsv")
            with open(source, "w", encoding="utf-8") as handle:
                handle.write("/var/log/test/access.log\tnot an access log\n")
            self.assertEqual(web_access_parser.main([
                "--input", source, "--output", output, "--format", "auto",
            ]), 0)
            with open(output, encoding="utf-8") as handle:
                rows = handle.read().splitlines()
            self.assertEqual(len(rows), 2)
            self.assertIn("\tPARTIAL_PARSE\t", rows[1])
            self.assertEqual(len(rows[1].rsplit("\t", 1)[-1]), 64)


if __name__ == "__main__":
    unittest.main()
