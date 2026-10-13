"""Tests for smbhunter.filters — classification, noise detection, content grep."""

import pytest

from smbhunter.tiers import CRITICAL, HIGH, MEDIUM, LOW, INFO
from smbhunter.filters import (
    classify_file, match_content, in_system_noise, _get_ext, SKIP_SHARES,
)


# ── _get_ext ──────────────────────────────────────────────────────────────────

class TestGetExt:
    def test_normal_extension(self):
        assert _get_ext("report.xlsx") == ".xlsx"

    def test_dotfile(self):
        assert _get_ext(".env") == ".env"

    def test_dotfile_gitconfig(self):
        assert _get_ext(".gitconfig") == ".gitconfig"

    def test_no_extension(self):
        assert _get_ext("readme") == ""

    def test_double_extension(self):
        assert _get_ext("backup.tar.gz") == ".gz"

    def test_uppercase_normalised(self):
        assert _get_ext("notes.txt") == ".txt"


# ── in_system_noise ───────────────────────────────────────────────────────────

class TestInSystemNoise:
    def test_admin_share_always_noise(self):
        assert in_system_noise("ADMIN$", "anything\\here") is True

    def test_admin_share_case_insensitive(self):
        assert in_system_noise("admin$", "Windows\\System32\\config") is True

    def test_c_dollar_system_path(self):
        assert in_system_noise("C$", "Windows\\System32\\drivers") is True

    def test_c_dollar_user_path(self):
        assert in_system_noise("C$", "Users\\admin\\Desktop\\passwords.txt") is False

    def test_named_share_never_noise(self):
        assert in_system_noise("IT-Dept", "Windows\\System32\\fake") is False

    def test_empty_path(self):
        assert in_system_noise("C$", "") is False


# ── classify_file ─────────────────────────────────────────────────────────────

class TestClassifyFile:
    def test_kdbx_critical(self):
        assert classify_file("passwords.kdbx", "\\Shared\\passwords.kdbx") == CRITICAL

    def test_pem_critical(self):
        assert classify_file("server.pem", "\\certs\\server.pem") == CRITICAL

    def test_ps1_high(self):
        assert classify_file("collect.ps1", "\\Scripts\\collect.ps1") == HIGH

    def test_bat_high(self):
        assert classify_file("startup.bat", "\\Scripts\\startup.bat") == HIGH

    def test_config_medium(self):
        assert classify_file("web.config", "\\App\\web.config") == MEDIUM

    def test_env_medium(self):
        assert classify_file(".env", "\\App\\.env") == MEDIUM

    def test_xlsx_low(self):
        assert classify_file("report.xlsx", "\\Docs\\report.xlsx") == LOW

    def test_unknown_ext_info(self):
        assert classify_file("readme", "\\readme") == INFO

    def test_password_keyword_critical(self):
        assert classify_file("password_list.txt", "\\Shared\\password_list.txt") == CRITICAL

    def test_cpassword_keyword_critical(self):
        assert classify_file("cpassword_backup.xml", "\\GPO\\cpassword_backup.xml") == CRITICAL

    def test_unattend_keyword_critical(self):
        assert classify_file("unattend.xml", "\\Sysprep\\unattend.xml") == CRITICAL

    def test_token_keyword_high(self):
        assert classify_file("token_store.json", "\\config\\token_store.json") == HIGH

    def test_admin_keyword_medium(self):
        assert classify_file("admin_guide.pdf", "\\Docs\\admin_guide.pdf") == MEDIUM

    def test_c_dollar_system_path_demoted(self):
        assert classify_file("deploy.ps1", "Windows\\System32\\deploy.ps1", "C$") == INFO

    def test_admin_dollar_demotes_keyword_to_info(self):
        assert classify_file("password_list.txt", "\\password_list.txt", "ADMIN$") == INFO

    def test_admin_dollar_preserves_critical_ext(self):
        assert classify_file("data.kdbx", "\\data.kdbx", "ADMIN$") == CRITICAL

    def test_named_share_not_demoted(self):
        assert classify_file("collect.ps1", "\\Scripts\\collect.ps1", "IT-Dept") == HIGH

    def test_deploy_keyword_overrides_ext(self):
        assert classify_file("deploy.ps1", "\\Scripts\\deploy.ps1") == MEDIUM

    def test_keyword_in_path(self):
        assert classify_file("notes.txt", "\\password_vault\\notes.txt") == CRITICAL


# ── match_content ─────────────────────────────────────────────────────────────

class TestMatchContent:
    def test_password_match(self):
        text = "some config\ndb_password = SuperSecret123\nother stuff"
        hits = match_content(text)
        assert len(hits) == 1
        assert hits[0][0] == CRITICAL
        assert "SuperSecret123" in hits[0][3]

    def test_private_key(self):
        text = "-----BEGIN PRIVATE KEY-----"
        hits = match_content(text)
        assert len(hits) == 1
        assert hits[0][0] == CRITICAL

    def test_aws_key(self):
        text = "access_key = AKIAIOSFODNN7EXAMPLE"
        hits = match_content(text)
        assert len(hits) == 1
        assert hits[0][0] == HIGH

    def test_github_pat(self):
        text = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        hits = match_content(text)
        assert len(hits) >= 1
        tiers = [h[0] for h in hits]
        assert CRITICAL in tiers or HIGH in tiers

    def test_net_use_creds(self):
        text = 'net use \\\\server\\share /user:admin P@ssw0rd'
        hits = match_content(text)
        assert len(hits) >= 1
        assert hits[0][0] == CRITICAL

    def test_publickey_token_no_match(self):
        text = "PublicKeyToken=b77a5c561934e089"
        hits = match_content(text)
        token_hits = [h for h in hits if "publickey" in h[1].lower() or "token" in h[1].lower()]
        assert len(token_hits) == 0

    def test_dedup_same_line(self):
        text = "root_password=R00t!2024"
        hits = match_content(text)
        assert len(hits) == 1

    def test_highest_tier_wins(self):
        text = "secret = AKIAIOSFODNN7EXAMPLE"
        hits = match_content(text)
        assert len(hits) == 1

    def test_extra_pattern(self):
        text = "ACME\\svc.backup connected"
        hits = match_content(text, extra_patterns=[r'ACME\\svc\.'])
        assert len(hits) == 1
        assert hits[0][0] == HIGH

    def test_invalid_extra_pattern_ignored(self):
        text = "some text"
        hits = match_content(text, extra_patterns=["[invalid"])
        assert len(hits) == 0

    def test_no_matches(self):
        text = "this is a completely normal text file\nwith nothing interesting"
        hits = match_content(text)
        assert len(hits) == 0

    def test_line_numbers(self):
        text = "line one\npassword = abc123\nline three"
        hits = match_content(text)
        assert hits[0][2] == 2

    def test_line_truncated(self):
        text = "password = " + "A" * 500
        hits = match_content(text)
        assert len(hits[0][3]) <= 200

    def test_multiple_lines_matched(self):
        text = "password = abc\nother\napi_key = xyz123"
        hits = match_content(text)
        assert len(hits) == 2
        assert hits[0][2] < hits[1][2]


# ── SKIP_SHARES ───────────────────────────────────────────────────────────────

class TestSkipShares:
    def test_ipc_skipped(self):
        assert "ipc$" in SKIP_SHARES

    def test_print_skipped(self):
        assert "print$" in SKIP_SHARES
