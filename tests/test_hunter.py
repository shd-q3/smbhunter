"""Tests for smbhunter.hunter — target expansion, scoring, dedup, spider logic."""

import os
import tempfile
from argparse import Namespace
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from smbhunter.hunter import SMBHunter, INTERESTING_SHARE_NAMES, SMB_DIALECTS
from smbhunter.tiers import CRITICAL, HIGH, MEDIUM, LOW, INFO


def _base_args(**overrides):
    defaults = dict(
        targets="127.0.0.1",
        username="admin", password="pass", hash=None, domain=".",
        kerberos=False, dc_ip=None, guest=False,
        after=None, min_tier="LOW", depth=10, max_size=50,
        exclude_dirs=None, exclude_ext=None, recon=False, content=False,
        pattern=None, shares=None, loot=None, write_check=False,
        delay=0, threads=1, timeout=5, resume=False,
        output=None, csv=None, logfile=None, debug=False,
    )
    defaults.update(overrides)
    return Namespace(**defaults)


# ── Target expansion ──────────────────────────────────────────────────────────

class TestExpandTargets:
    def test_single_host(self):
        h = SMBHunter(_base_args(targets="10.0.0.5"))
        assert h._expand_targets() == ["10.0.0.5"]

    def test_hostname(self):
        h = SMBHunter(_base_args(targets="dc01.corp.local"))
        assert h._expand_targets() == ["dc01.corp.local"]

    def test_cidr_slash30(self):
        h = SMBHunter(_base_args(targets="192.168.1.0/30"))
        hosts = h._expand_targets()
        assert hosts == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_slash32(self):
        h = SMBHunter(_base_args(targets="10.0.0.5/32"))
        assert h._expand_targets() == ["10.0.0.5"]

    def test_cidr_slash24_count(self):
        h = SMBHunter(_base_args(targets="10.0.0.0/24"))
        hosts = h._expand_targets()
        assert len(hosts) == 254

    def test_target_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("10.0.0.1\n10.0.0.2\n# comment\n\n10.0.0.3\n")
            f.flush()
            path = f.name
        try:
            h = SMBHunter(_base_args(targets=path))
            hosts = h._expand_targets()
            assert hosts == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        finally:
            os.unlink(path)

    def test_target_file_with_cidr(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("10.0.0.0/30\ndc01.corp.local\n")
            f.flush()
            path = f.name
        try:
            h = SMBHunter(_base_args(targets=path))
            hosts = h._expand_targets()
            assert hosts == ["10.0.0.1", "10.0.0.2", "dc01.corp.local"]
        finally:
            os.unlink(path)


# ── Share scoring ─────────────────────────────────────────────────────────────

class TestScoreShare:
    def setup_method(self):
        self.h = SMBHunter(_base_args())

    def test_interesting_name_boost(self):
        score = self.h._score_share("backup", "", True, False, 5, 10)
        assert score >= 50

    def test_writable_boost(self):
        s1 = self.h._score_share("Data", "", True, True, 0, 0)
        s2 = self.h._score_share("Data", "", True, False, 0, 0)
        assert s1 > s2
        assert s1 - s2 == 25

    def test_readable_boost(self):
        s1 = self.h._score_share("Data", "", True, False, 0, 0)
        s2 = self.h._score_share("Data", "", False, False, 0, 0)
        assert s1 - s2 == 10

    def test_files_boost_capped(self):
        s1 = self.h._score_share("Data", "", True, False, 0, 100)
        s2 = self.h._score_share("Data", "", True, False, 0, 5)
        assert s1 == s2 + 15

    def test_dirs_boost_capped(self):
        s1 = self.h._score_share("Data", "", True, False, 50, 0)
        s2 = self.h._score_share("Data", "", True, False, 1, 0)
        assert s1 == s2 + 18

    def test_remark_keyword_boost(self):
        s1 = self.h._score_share("X", "User home directories", True, False, 0, 0)
        s2 = self.h._score_share("X", "", True, False, 0, 0)
        assert s1 - s2 == 10

    def test_admin_share_boost(self):
        s1 = self.h._score_share("C$", "", True, False, 0, 0)
        s2 = self.h._score_share("SomeShare", "", True, False, 0, 0)
        assert s1 > s2

    def test_password_in_name(self):
        score = self.h._score_share("passwords", "", True, False, 0, 0)
        assert score >= 60


# ── Tier filtering ────────────────────────────────────────────────────────────

class TestTierPasses:
    def test_critical_passes_low(self):
        h = SMBHunter(_base_args(min_tier="LOW"))
        assert h._tier_passes(CRITICAL) is True

    def test_info_fails_low(self):
        h = SMBHunter(_base_args(min_tier="LOW"))
        assert h._tier_passes(INFO) is False

    def test_high_passes_high(self):
        h = SMBHunter(_base_args(min_tier="HIGH"))
        assert h._tier_passes(HIGH) is True

    def test_medium_fails_high(self):
        h = SMBHunter(_base_args(min_tier="HIGH"))
        assert h._tier_passes(MEDIUM) is False

    def test_info_passes_info(self):
        h = SMBHunter(_base_args(min_tier="INFO"))
        assert h._tier_passes(INFO) is True


# ── Epoch conversion ──────────────────────────────────────────────────────────

class TestEpochToDt:
    def setup_method(self):
        self.h = SMBHunter(_base_args())

    def test_valid_epoch(self):
        dt = self.h._epoch_to_dt(1700000000)
        assert dt is not None
        assert dt.year == 2023

    def test_zero_epoch(self):
        assert self.h._epoch_to_dt(0) is None

    def test_negative_epoch(self):
        assert self.h._epoch_to_dt(-1) is None

    def test_none_epoch(self):
        assert self.h._epoch_to_dt(None) is None


# ── File dedup ────────────────────────────────────────────────────────────────

class TestFileDedup:
    def test_seen_files_init(self):
        h = SMBHunter(_base_args())
        assert isinstance(h._seen_files, set)
        assert len(h._seen_files) == 0

    def test_dedup_key_blocks_duplicate(self):
        h = SMBHunter(_base_args(min_tier="INFO"))
        mtime_dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        key = ("10.0.0.1", "deploy.ps1", 1024, int(mtime_dt.timestamp()))
        h._seen_files.add(key)
        assert key in h._seen_files
        h._seen_files.add(key)
        assert len(h._seen_files) == 1

    def test_different_hosts_not_deduped(self):
        h = SMBHunter(_base_args())
        k1 = ("10.0.0.1", "deploy.ps1", 1024, 1700000000)
        k2 = ("10.0.0.2", "deploy.ps1", 1024, 1700000000)
        h._seen_files.add(k1)
        h._seen_files.add(k2)
        assert len(h._seen_files) == 2

    def test_different_sizes_not_deduped(self):
        h = SMBHunter(_base_args())
        k1 = ("10.0.0.1", "deploy.ps1", 1024, 1700000000)
        k2 = ("10.0.0.1", "deploy.ps1", 2048, 1700000000)
        h._seen_files.add(k1)
        h._seen_files.add(k2)
        assert len(h._seen_files) == 2


# ── Connection (mocked) ──────────────────────────────────────────────────────

class TestConnect:
    @patch("smbhunter.hunter.SMBConnection")
    def test_password_auth(self, mock_cls):
        mock_conn = MagicMock()
        mock_cls.return_value = mock_conn
        h = SMBHunter(_base_args(username="admin", password="pass", domain="CORP"))
        conn = h.connect("10.0.0.1")
        mock_cls.assert_called_once_with("10.0.0.1", "10.0.0.1", sess_port=445, timeout=5)
        mock_conn.login.assert_called_once_with("admin", "pass", "CORP")
        assert conn is mock_conn

    @patch("smbhunter.hunter.SMBConnection")
    def test_hash_auth(self, mock_cls):
        mock_conn = MagicMock()
        mock_cls.return_value = mock_conn
        h = SMBHunter(_base_args(
            username="admin", password="",
            hash="aad3b435b51404ee:ntlmhash", domain="CORP",
        ))
        conn = h.connect("10.0.0.1")
        mock_conn.login.assert_called_once_with(
            "admin", "", "CORP",
            lmhash="aad3b435b51404ee", nthash="ntlmhash",
        )
        assert conn is mock_conn

    @patch("smbhunter.hunter.SMBConnection")
    def test_kerberos_auth(self, mock_cls):
        mock_conn = MagicMock()
        mock_cls.return_value = mock_conn
        h = SMBHunter(_base_args(kerberos=True, dc_ip="10.0.0.1", domain="CORP"))
        conn = h.connect("10.0.0.1")
        mock_conn.kerberosLogin.assert_called_once()

    @patch("smbhunter.hunter.SMBConnection")
    def test_guest_auth(self, mock_cls):
        mock_conn = MagicMock()
        mock_cls.return_value = mock_conn
        h = SMBHunter(_base_args(guest=True, username="", password=""))
        conn = h.connect("10.0.0.1")
        mock_conn.login.assert_called_once_with("Guest", "")

    @patch("smbhunter.hunter.SMBConnection")
    def test_connection_failure(self, mock_cls):
        mock_cls.side_effect = Exception("Connection refused")
        h = SMBHunter(_base_args())
        conn = h.connect("10.0.0.1")
        assert conn is None


# ── list_shares (mocked) ─────────────────────────────────────────────────────

class TestListShares:
    def _make_share(self, name, stype=0, remark=""):
        s = MagicMock()
        s.__getitem__ = lambda self_, k: {
            "shi1_netname": name + "\x00",
            "shi1_type": stype,
            "shi1_remark": remark + "\x00",
        }[k]
        return s

    @patch("smbhunter.hunter.SMBConnection")
    def test_list_shares_basic(self, mock_cls):
        mock_conn = MagicMock()
        mock_conn.listShares.return_value = [
            self._make_share("IT-Dept", remark="IT shared files"),
            self._make_share("C$", remark="Default share"),
            self._make_share("IPC$", remark="Remote IPC"),
        ]
        h = SMBHunter(_base_args())
        shares = h.list_shares(mock_conn)
        names = [s["name"] for s in shares]
        assert "IT-Dept" in names
        assert "C$" in names
        assert "IPC$" not in names

    @patch("smbhunter.hunter.SMBConnection")
    def test_list_shares_bytes_remark(self, mock_cls):
        s = MagicMock()
        s.__getitem__ = lambda self_, k: {
            "shi1_netname": "Share\x00",
            "shi1_type": 0,
            "shi1_remark": b"bytes remark\x00",
        }[k]
        mock_conn = MagicMock()
        mock_conn.listShares.return_value = [s]
        h = SMBHunter(_base_args())
        shares = h.list_shares(mock_conn)
        assert shares[0]["remark"] == "bytes remark"


# ── Write check (mocked) ─────────────────────────────────────────────────────

class TestWriteCheck:
    def test_writable(self):
        mock_conn = MagicMock()
        h = SMBHunter(_base_args())
        assert h._check_write(mock_conn, "Share") is True
        mock_conn.putFile.assert_called_once()
        mock_conn.deleteFile.assert_called_once()

    def test_not_writable(self):
        mock_conn = MagicMock()
        mock_conn.putFile.side_effect = Exception("ACCESS_DENIED")
        h = SMBHunter(_base_args())
        assert h._check_write(mock_conn, "Share") is False


# ── Stats thread safety ──────────────────────────────────────────────────────

class TestStats:
    def test_inc_stat(self):
        h = SMBHunter(_base_args())
        h._inc_stat("files_seen", 5)
        h._inc_stat("files_seen", 3)
        assert h.stats["files_seen"] == 8

    def test_add_result(self):
        h = SMBHunter(_base_args())
        finding = {"host": "x", "tier": "HIGH", "path": "test"}
        h._add_result(finding)
        assert len(h.results) == 1
        assert h.results[0] is finding

    def test_add_error(self):
        h = SMBHunter(_base_args())
        h._add_error("10.0.0.1", "Share", "timeout")
        assert len(h.errors) == 1
        assert h.errors[0]["error"] == "timeout"


# ── SMB dialect detection ─────────────────────────────────────────────────────

class TestGetDialect:
    def test_smb2(self):
        conn = MagicMock()
        conn.getDialect.return_value = 0x0202
        assert SMBHunter._get_dialect(conn) == "SMB 2.0.2"

    def test_smb3(self):
        conn = MagicMock()
        conn.getDialect.return_value = 0x0311
        assert SMBHunter._get_dialect(conn) == "SMB 3.1.1"

    def test_smb1(self):
        conn = MagicMock()
        conn.getDialect.return_value = 0x0002
        assert SMBHunter._get_dialect(conn) == "SMB1"

    def test_unknown_dialect(self):
        conn = MagicMock()
        conn.getDialect.return_value = 0x9999
        assert SMBHunter._get_dialect(conn) == "0x9999"

    def test_exception(self):
        conn = MagicMock()
        conn.getDialect.side_effect = Exception("not supported")
        assert SMBHunter._get_dialect(conn) is None

    def test_dialect_map_complete(self):
        expected = {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
        assert set(SMB_DIALECTS.keys()) == expected


# ── Exclude extension ─────────────────────────────────────────────────────────

class TestExcludeExt:
    def test_exclude_ext_normalised(self):
        h = SMBHunter(_base_args(exclude_ext=[".dll", "exe", ".sys"]))
        assert h._exclude_ext == {".dll", ".exe", ".sys"}

    def test_exclude_ext_empty(self):
        h = SMBHunter(_base_args(exclude_ext=None))
        assert h._exclude_ext == set()

    def test_exclude_ext_dot_prefix_added(self):
        h = SMBHunter(_base_args(exclude_ext=["dll"]))
        assert ".dll" in h._exclude_ext


# ── Progress counter ──────────────────────────────────────────────────────────

class TestProgress:
    def test_progress_increments(self):
        h = SMBHunter(_base_args())
        h._total_hosts = 5
        h._report_progress()
        assert h._hosts_done == 1
        h._report_progress()
        assert h._hosts_done == 2

    def test_no_progress_for_single_host(self, capsys):
        h = SMBHunter(_base_args())
        h._total_hosts = 1
        h._report_progress()
        captured = capsys.readouterr()
        assert "[1/1]" not in captured.out


# ── Resume ────────────────────────────────────────────────────────────────────

class TestResume:
    def test_resume_skips_scanned_hosts(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            f.write('{"host":"10.0.0.1","share":"C$","path":"test"}\n')
            f.write('{"host":"10.0.0.2","share":"Data","path":"test"}\n')
            jsonl_path = f.name

        json_path = jsonl_path[:-1]
        try:
            h = SMBHunter(_base_args(
                output=json_path, resume=True,
                targets="10.0.0.1",
            ))
            seen = h._load_resume_hosts()
            assert "10.0.0.1" in seen
            assert "10.0.0.2" in seen
            assert "10.0.0.3" not in seen
        finally:
            os.unlink(jsonl_path)
            if os.path.exists(json_path):
                os.unlink(json_path)

    def test_resume_no_file(self):
        h = SMBHunter(_base_args(output="/tmp/nonexistent_test.json", resume=True))
        seen = h._load_resume_hosts()
        assert len(seen) == 0

    def test_resume_disabled(self):
        h = SMBHunter(_base_args(output="/tmp/test.json", resume=False))
        seen = h._load_resume_hosts()
        assert len(seen) == 0
