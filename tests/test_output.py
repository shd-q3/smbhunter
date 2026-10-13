"""Tests for smbhunter.output — formatting, CSV/JSON report generation."""

import csv
import json
import os
import tempfile
from collections import defaultdict
from datetime import datetime, timezone

import pytest

from smbhunter.output import (
    human_size, write_json_report, write_csv_report,
    write_json_recon_report, write_csv_recon_report,
    print_dialect, print_progress,
)
from smbhunter.tiers import CRITICAL, HIGH, MEDIUM, LOW, INFO


# ── human_size ────────────────────────────────────────────────────────────────

class TestHumanSize:
    def test_bytes(self):
        assert human_size(512) == "512.0 B"

    def test_kb(self):
        assert human_size(2048) == "2.0 KB"

    def test_mb(self):
        assert human_size(5 * 1024 * 1024) == "5.0 MB"

    def test_gb(self):
        assert human_size(3 * 1024 ** 3) == "3.0 GB"

    def test_none(self):
        assert human_size(None) == "?"

    def test_zero(self):
        assert human_size(0) == "0.0 B"


# ── CSV hunt report ──────────────────────────────────────────────────────────

class TestWriteCsvReport:
    def test_csv_uses_line_text_not_pattern(self):
        results = [{
            "host": "10.0.0.1",
            "share": "IT-Dept",
            "path": "\\Scripts\\deploy.ps1",
            "filename": "deploy.ps1",
            "tier": HIGH,
            "size": 1024,
            "mtime": "2024-06-15T00:00:00+00:00",
            "content_hits": [{
                "tier": CRITICAL,
                "line": "db_password = SuperSecret123",
                "line_num": 5,
                "pattern": r"password\s*[=:]\s*\S+",
            }],
        }]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            path = f.name

        try:
            write_csv_report(path, results)
            with open(path) as f:
                reader = csv.reader(f)
                rows = list(reader)
            assert len(rows) == 2
            content_col = rows[1][-1]
            assert "SuperSecret123" in content_col
            assert "\\s*" not in content_col
        finally:
            os.unlink(path)

    def test_csv_empty_content(self):
        results = [{
            "host": "10.0.0.1",
            "share": "IT-Dept",
            "path": "\\passwords.kdbx",
            "filename": "passwords.kdbx",
            "tier": CRITICAL,
            "size": 4096,
            "mtime": None,
            "content_hits": [],
        }]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            path = f.name

        try:
            write_csv_report(path, results)
            with open(path) as f:
                reader = csv.reader(f)
                rows = list(reader)
            assert rows[1][-1] == ""
        finally:
            os.unlink(path)

    def test_csv_multiple_hits_semicolon_joined(self):
        results = [{
            "host": "10.0.0.1",
            "share": "DevOps",
            "path": "\\config.yml",
            "filename": "config.yml",
            "tier": CRITICAL,
            "size": 512,
            "mtime": None,
            "content_hits": [
                {"tier": CRITICAL, "line": "password = abc",
                 "line_num": 2, "pattern": r"password\s*[=:]\s*\S+"},
                {"tier": HIGH, "line": "api_key = xyz123",
                 "line_num": 5, "pattern": r"api[_-]?key\s*[=:]\s*\S+"},
            ],
        }]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            path = f.name

        try:
            write_csv_report(path, results)
            with open(path) as f:
                reader = csv.reader(f)
                rows = list(reader)
            content = rows[1][-1]
            assert "L2: password = abc" in content
            assert "L5: api_key = xyz123" in content
            assert "; " in content
        finally:
            os.unlink(path)


# ── JSON hunt report ──────────────────────────────────────────────────────────

class TestWriteJsonReport:
    def test_json_structure(self):
        from argparse import Namespace
        args = Namespace(
            targets="10.0.0.1", after=None, min_tier="LOW",
            depth=10, content=True,
        )
        stats = defaultdict(int, {"files_seen": 50, "readable_shares": 3})
        results = [{"host": "10.0.0.1", "tier": CRITICAL, "path": "\\test"}]
        errors = []

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        try:
            write_json_report(path, args, stats, results, errors)
            with open(path) as f:
                report = json.load(f)
            assert report["mode"] == "hunt"
            assert report["targets"] == "10.0.0.1"
            assert len(report["findings"]) == 1
            assert report["stats"]["files_seen"] == 50
        finally:
            os.unlink(path)


# ── CSV recon report ──────────────────────────────────────────────────────────

class TestWriteCsvReconReport:
    def test_recon_csv(self):
        recon = [{
            "host": "10.0.0.1",
            "hostname": "DC01",
            "share": "backup",
            "remark": "Backup share",
            "readable": True,
            "writable": True,
            "dirs": 5,
            "files": 20,
            "score": 75,
        }]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            path = f.name

        try:
            write_csv_recon_report(path, recon)
            with open(path) as f:
                reader = csv.reader(f)
                rows = list(reader)
            assert len(rows) == 2
            assert rows[0] == ["host", "hostname", "share", "remark",
                               "readable", "writable", "dirs", "files", "score"]
            assert rows[1][0] == "10.0.0.1"
            assert rows[1][2] == "backup"
            assert rows[1][-1] == "75"
        finally:
            os.unlink(path)


# ── JSON recon report ─────────────────────────────────────────────────────────

class TestWriteJsonReconReport:
    def test_recon_json(self):
        from argparse import Namespace
        args = Namespace(targets="10.0.0.0/24")
        stats = defaultdict(int, {"readable_shares": 5})
        recon = [{"host": "10.0.0.1", "share": "backup", "score": 75}]
        errors = []

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            path = f.name

        try:
            write_json_recon_report(path, args, stats, recon, errors)
            with open(path) as f:
                report = json.load(f)
            assert report["mode"] == "recon"
            assert len(report["shares"]) == 1
            assert report["shares"][0]["score"] == 75
        finally:
            os.unlink(path)


# ── Dialect and progress output ───────────────────────────────────────────────

class TestPrintDialect:
    def test_dialect_prints(self, capsys):
        print_dialect("SMB 3.1.1")
        out = capsys.readouterr().out
        assert "SMB 3.1.1" in out

    def test_smbv1_prints(self, capsys):
        print_dialect("SMB1")
        out = capsys.readouterr().out
        assert "SMB1" in out


class TestPrintProgress:
    def test_progress_format(self, capsys):
        print_progress(5, 20)
        out = capsys.readouterr().out
        assert "5/20" in out
        assert "25%" in out

    def test_progress_complete(self, capsys):
        print_progress(10, 10)
        out = capsys.readouterr().out
        assert "100%" in out
