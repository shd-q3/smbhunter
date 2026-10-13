"""Windows noise filtering and file classification logic."""

import os
import re

from smbhunter.tiers import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    ALL_TIERS, EXT_TIERS, KEYWORD_TIERS, CONTENT_PATTERNS, CONTENT_EXTS,
)

# ── Shares to always skip ──────────────────────────────────────────────────

SKIP_SHARES = {"ipc$", "print$"}

# ── Directories to skip (case-insensitive exact match on dir name) ──────────

SKIP_DIRS = {
    "windows", "system32", "syswow64", "winsxs", "assembly",
    "servicing", "microsoft.net", "installer", "panther",
    "prefetch", "fonts", "inf", "migration", "performance",
    "policydefinitions", "cursors", "globalization",
    "immersivecontrolpanel", "rescache", "diagnostics",
    "systemapps", "schemas", "systemresources",
    "microsoft shared", "windowspowershell", "windowsapps",
    "program files", "program files (x86)",
    "microsoft sdks", "reference assemblies",
    "v1.0", "media",
}

# ── Path segments indicating Windows OS noise ──────────────────────────────

SYSTEM_NOISE_PATHS = {
    "\\windows\\", "\\system32\\", "\\syswow64\\", "\\winsxs\\",
    "\\systemapps\\", "\\schemas\\", "\\servicing\\", "\\assembly\\",
    "\\program files\\", "\\program files (x86)\\", "\\microsoft\\",
    "\\windowsapps\\", "\\windowspowershell\\",
    "\\microsoft.net\\", "\\reference assemblies\\",
    "\\windows defender\\", "\\definition updates\\",
    "\\systemresources\\", "\\media\\",
}


def in_system_noise(share, path):
    """True if path is inside a known Windows system directory on ADMIN$/C$."""
    if share.upper() == "ADMIN$":
        return True
    if share.upper() != "C$":
        return False
    full = f"\\{path}".lower()
    return any(seg in full for seg in SYSTEM_NOISE_PATHS)


def _get_ext(name_lower):
    """Extract extension, treating dotfiles (.env, .gitconfig) as their own ext."""
    ext = os.path.splitext(name_lower)[1]
    if not ext and name_lower.startswith('.'):
        ext = name_lower
    return ext


def classify_file(filename, path, share=""):
    """Return severity tier based on filename, extension, keywords, and location."""
    name_lower = filename.lower()
    ext = _get_ext(name_lower)
    full_lower = path.lower()
    noisy = in_system_noise(share, path)

    for tier in (CRITICAL, HIGH, MEDIUM):
        for kw in KEYWORD_TIERS[tier]:
            if re.search(r'(?:^|[\W_])' + re.escape(kw) + r'(?:[\W_]|$)', name_lower) or \
               re.search(r'(?:^|[\W_])' + re.escape(kw) + r'(?:[\W_]|$)', full_lower):
                return INFO if noisy else tier

    for tier in (CRITICAL, HIGH, MEDIUM, LOW):
        if ext in EXT_TIERS[tier]:
            if noisy and tier in (MEDIUM, LOW):
                return INFO
            return tier

    return INFO


def match_content(text, extra_patterns=None):
    """Return deduped list of (tier, pattern, line_num, line_text) matches.

    Each line appears at most once, at the highest matched tier.
    """
    MAX_LINE = 2000
    hits = {}
    for line_num, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE:
            continue
        for tier in (CRITICAL, HIGH):
            for pattern in CONTENT_PATTERNS[tier]:
                if re.search(pattern, line, re.IGNORECASE):
                    if line_num not in hits or \
                            ALL_TIERS.index(tier) < ALL_TIERS.index(hits[line_num][0]):
                        hits[line_num] = (tier, pattern, line_num, line.strip()[:200])

    if extra_patterns:
        for line_num, line in enumerate(text.splitlines(), 1):
            if len(line) > MAX_LINE:
                continue
            for pattern in extra_patterns:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        tier = HIGH
                        if line_num not in hits or \
                                ALL_TIERS.index(tier) < ALL_TIERS.index(hits[line_num][0]):
                            hits[line_num] = (tier, pattern, line_num, line.strip()[:200])
                except re.error:
                    pass

    return sorted(hits.values(), key=lambda x: x[2])
