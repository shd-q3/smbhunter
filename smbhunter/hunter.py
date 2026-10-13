"""Core SMB spider and content searcher."""

import json
import logging
import os
import re
import tempfile
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from impacket.smbconnection import SMBConnection, SessionError

from smbhunter.tiers import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO, ALL_TIERS,
    COLORS, RESET, CONTENT_EXTS, CONTENT_FILENAMES,
)
from smbhunter.filters import (
    SKIP_SHARES, SKIP_DIRS, classify_file, match_content, _get_ext,
)
from smbhunter.output import (
    print_finding, print_banner, print_summary,
)

log = logging.getLogger("smbhunter")


class SMBHunter:
    def __init__(self, args):
        self.args = args
        self.after_dt = None
        if args.after:
            self.after_dt = datetime.strptime(args.after, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        self.min_tier = args.min_tier
        self.results = []
        self.stats = defaultdict(int)
        self.errors = []
        self._lock = threading.Lock()
        self._delay = getattr(args, "delay", 0) / 1000.0 if getattr(args, "delay", 0) else 0

    def _inc_stat(self, key, n=1):
        with self._lock:
            self.stats[key] += n

    def _add_result(self, finding):
        with self._lock:
            self.results.append(finding)

    def _add_error(self, host, share, error):
        with self._lock:
            self.errors.append({"host": host, "share": share or "", "error": str(error)})
        log.error("%s [%s] %s", host, share or "-", error)

    def _tier_passes(self, tier):
        return ALL_TIERS.index(tier) <= ALL_TIERS.index(self.min_tier)

    def _epoch_to_dt(self, epoch_secs):
        if not epoch_secs or epoch_secs <= 0:
            return None
        try:
            return datetime.fromtimestamp(epoch_secs, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None

    # ── Connection ──────────────────────────────────────────────────────────

    def connect(self, host):
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=self.args.timeout)
            if self.args.hash:
                lm, nt = self.args.hash.split(":")
                conn.login(self.args.username, "", self.args.domain, lmhash=lm, nthash=nt)
            else:
                conn.login(self.args.username, self.args.password, self.args.domain)
            return conn
        except Exception as e:
            print(f"  [-] {host}: connection failed — {e}", flush=True)
            return None

    def list_shares(self, conn):
        shares = []
        try:
            for share in conn.listShares():
                name = share["shi1_netname"][:-1]
                if name.lower() not in SKIP_SHARES:
                    shares.append(name)
        except SessionError:
            pass
        return shares

    def can_read(self, conn, share):
        try:
            conn.listPath(share, "\\*")
            return True
        except SessionError:
            return False

    # ── Directory spider ────────────────────────────────────────────────────

    def spider_dir(self, conn, host, share, path, depth):
        """Spider a directory. Returns the (possibly reconnected) conn, or None on fatal failure."""
        if depth > self.args.depth:
            return conn

        try:
            entries = conn.listPath(share, path + "*")
        except SessionError:
            return conn
        except Exception as e:
            log.warning("Connection error at %s\\%s: %s", share, path, e)
            conn = self.connect(host)
            if not conn:
                self._add_error(host, share, f"reconnect failed at {path}")
                return None
            try:
                entries = conn.listPath(share, path + "*")
            except Exception:
                return conn

        dirs_to_recurse = []

        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue

            full_path = path + name
            is_dir = entry.is_directory()
            size = entry.get_filesize()
            try:
                mtime = self._epoch_to_dt(entry.get_mtime_epoch())
            except Exception:
                mtime = None

            self._inc_stat("total_items")

            if is_dir:
                name_lower = name.lower()
                if name_lower in SKIP_DIRS:
                    self._inc_stat("skipped_dirs")
                    continue

                if self.after_dt and re.match(r'^(19|20)\d{2}$', name):
                    try:
                        if int(name) < self.after_dt.year:
                            self._inc_stat("skipped_old_dirs")
                            continue
                    except ValueError:
                        pass

                if self.args.exclude_dirs:
                    if any(ex.lower() in name_lower for ex in self.args.exclude_dirs):
                        self._inc_stat("skipped_dirs")
                        continue

                dirs_to_recurse.append(full_path + "\\")
                continue

            # ── File processing ─────────────────────────────────────────────

            self._inc_stat("files_seen")

            if self.after_dt and mtime and mtime < self.after_dt:
                self._inc_stat("skipped_old_files")
                continue

            if self.args.max_size and size and size > self.args.max_size * 1024 * 1024:
                self._inc_stat("skipped_large")
                continue

            tier = classify_file(name, full_path, share)

            content_hits = []
            if self.args.content:
                name_lower = name.lower()
                ext = _get_ext(name_lower)
                if (ext in CONTENT_EXTS or name_lower in CONTENT_FILENAMES) \
                        and size and size < 1024 * 1024:
                    content_hits = self._grep_file(conn, share, full_path)
                    if content_hits:
                        for ct, _, _, _ in content_hits:
                            if ALL_TIERS.index(ct) < ALL_TIERS.index(tier):
                                tier = ct

            if not self._tier_passes(tier):
                continue

            finding = {
                "host": host,
                "share": share,
                "path": full_path,
                "filename": name,
                "size": size,
                "mtime": mtime.isoformat() if mtime else None,
                "tier": tier,
                "content_hits": [
                    {"tier": t, "line": l, "line_num": ln, "match": m}
                    for t, m, ln, l in content_hits
                ],
            }

            self._add_result(finding)
            log.info("%s [%s] %s — %s (%s)", host, share, full_path, tier,
                     f"{len(content_hits)} content hits" if content_hits else "filename/ext only")
            print_finding(host, share, full_path, tier, size, mtime, content_hits)

            if self._delay:
                time.sleep(self._delay)

        for dir_path in dirs_to_recurse:
            conn = self.spider_dir(conn, host, share, dir_path, depth + 1)
            if conn is None:
                return None

        return conn

    # ── Content grep ────────────────────────────────────────────────────────

    def _grep_file(self, conn, share, path):
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".smbtmp")
            with os.fdopen(fd, "wb") as tmp:
                conn.getFile(share, path, tmp.write)
            with open(tmp_path, "rb") as f:
                try:
                    text = f.read().decode("utf-8", errors="replace")
                except Exception:
                    return []
            return match_content(text)
        except Exception:
            return []
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    sz = os.path.getsize(tmp_path)
                    with open(tmp_path, "wb") as f:
                        f.write(b'\x00' * sz)
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # ── Per-host entry point ────────────────────────────────────────────────

    def hunt_host(self, host):
        print(f"\n[*] {host}", flush=True)
        log.info("Connecting to %s", host)
        conn = self.connect(host)
        if not conn:
            self._add_error(host, "", "initial connection failed")
            return

        try:
            signing = conn.isSigningRequired()
            label = "required" if signing else "NOT required"
            print(f"  [i] SMB signing: {label}", flush=True)
            log.info("%s SMB signing: %s", host, label)
            self._inc_stat("signing_required" if signing else "signing_not_required")
        except Exception:
            pass

        shares = self.list_shares(conn)
        if hasattr(self.args, "shares") and self.args.shares:
            allowed = {s.strip().lower() for s in self.args.shares.split(",")}
            shares = [s for s in shares if s.lower() in allowed]

        for share in shares:
            if not self.can_read(conn, share):
                self._inc_stat("unreadable_shares")
                continue

            self._inc_stat("readable_shares")
            print(f"  [+] {share}", flush=True)

            if share.upper() in ("NETLOGON", "SYSVOL"):
                c = COLORS.get(HIGH, "")
                print(f"  {c}[!] {share} — login scripts likely contain credentials{RESET}", flush=True)

            conn = self.spider_dir(conn, host, share, "\\", 0)
            if conn is None:
                log.warning("Lost connection to %s during %s, reconnecting", host, share)
                conn = self.connect(host)
                if not conn:
                    self._add_error(host, share, "reconnect failed, skipping remaining shares")
                    return

        try:
            conn.logoff()
        except Exception:
            pass

    # ── Main run loop ───────────────────────────────────────────────────────

    def _setup_logging(self):
        level = logging.DEBUG if getattr(self.args, "debug", False) else logging.INFO
        log.setLevel(level)
        logfile = getattr(self.args, "logfile", None)
        if logfile:
            fh = logging.FileHandler(logfile)
            fh.setLevel(level)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"))
            log.addHandler(fh)
            log.info("smbhunter started — logging to %s", logfile)

    def run(self):
        self._setup_logging()
        hosts = []
        if os.path.isfile(self.args.targets):
            with open(self.args.targets) as f:
                hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        else:
            hosts = [self.args.targets]

        log.info("Targets: %d, content=%s, min_tier=%s, depth=%d",
                 len(hosts), self.args.content, self.min_tier, self.args.depth)
        print_banner(len(hosts), self.args)
        start = time.time()

        if self.args.threads > 1 and len(hosts) > 1:
            with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
                futures = {ex.submit(self.hunt_host, h): h for h in hosts}
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        host = futures[f]
                        self._add_error(host, "", str(e))
                        print(f"  [-] {host}: {e}", flush=True)
        else:
            for host in hosts:
                self.hunt_host(host)

        elapsed = time.time() - start
        log.info("Scan complete in %.1fs — %d findings, %d errors",
                 elapsed, len(self.results), len(self.errors))
        print_summary(elapsed, self.stats, self.results, self.errors,
                      self.args.output, self.args)
