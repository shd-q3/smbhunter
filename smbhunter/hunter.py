"""Core SMB spider and content searcher."""

import ipaddress
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
from io import BytesIO

from impacket.smbconnection import SMBConnection, SessionError

from smbhunter.tiers import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO, ALL_TIERS,
    COLORS, RESET, CONTENT_EXTS, CONTENT_FILENAMES,
)
from smbhunter.filters import (
    SKIP_SHARES, SKIP_DIRS, classify_file, match_content, _get_ext,
)
from smbhunter.output import (
    print_finding, print_banner, print_summary, supports_color,
    print_share, print_host_header, print_share_warning, print_loot,
    print_signing, print_recon_share,
)

log = logging.getLogger("smbhunter")

INTERESTING_SHARE_NAMES = {
    "it", "admin", "backup", "backups", "deploy", "devops", "dev",
    "finance", "hr", "payroll", "accounting", "legal", "confidential",
    "private", "secret", "secrets", "credentials", "certs", "certificates",
    "keys", "ssh", "vpn", "passwords", "dba", "database", "sql",
    "scripts", "tools", "software", "install", "images", "iso",
    "users", "profiles", "home", "homes", "userdata", "shared",
    "common", "public", "department", "departments", "projects",
    "engineering", "security", "infosec", "audit", "compliance",
    "executive", "management", "board", "strategic",
}


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
        self._jsonl_path = None
        self._extra_patterns = getattr(args, "pattern", None) or []
        self._recon_results = []
        self._seen_files = set()

    def _inc_stat(self, key, n=1):
        with self._lock:
            self.stats[key] += n

    def _add_result(self, finding):
        with self._lock:
            self.results.append(finding)
        self._stream_finding(finding)

    def _add_error(self, host, share, error):
        with self._lock:
            self.errors.append({"host": host, "share": share or "", "error": str(error)})
        log.error("%s [%s] %s", host, share or "-", error)

    def _stream_finding(self, finding):
        if not self._jsonl_path:
            return
        with self._lock:
            try:
                with open(self._jsonl_path, "a") as f:
                    f.write(json.dumps(finding, default=str) + "\n")
            except OSError:
                pass

    def _tier_passes(self, tier):
        return ALL_TIERS.index(tier) <= ALL_TIERS.index(self.min_tier)

    def _epoch_to_dt(self, epoch_secs):
        if not epoch_secs or epoch_secs <= 0:
            return None
        try:
            return datetime.fromtimestamp(epoch_secs, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None

    # ── Target expansion ───────────────────────────────────────────────────

    def _expand_targets(self):
        if os.path.isfile(self.args.targets):
            with open(self.args.targets) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        else:
            lines = [self.args.targets]

        hosts = []
        for line in lines:
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.num_addresses > 1:
                    hosts.extend(str(ip) for ip in net.hosts())
                else:
                    hosts.append(str(net.network_address))
            except ValueError:
                hosts.append(line)
        return hosts

    # ── Connection ──────────────────────────────────────────────────────────

    def connect(self, host):
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=self.args.timeout)
            if getattr(self.args, "kerberos", False):
                conn.kerberosLogin(
                    self.args.username, self.args.password, self.args.domain,
                    kdcHost=getattr(self.args, "dc_ip", None),
                    useCache=True,
                )
            elif getattr(self.args, "guest", False):
                try:
                    conn.login("Guest", "")
                except SessionError:
                    conn.login("", "")
            elif self.args.hash:
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
                stype = share["shi1_type"]
                try:
                    raw = share["shi1_remark"]
                    remark = raw[:-1] if isinstance(raw, str) else \
                             raw.rstrip(b"\x00").decode("utf-8", errors="replace")
                except Exception:
                    remark = ""
                if name.lower() not in SKIP_SHARES:
                    shares.append({"name": name, "type": stype, "remark": remark})
        except SessionError:
            pass
        return shares

    def can_read(self, conn, share):
        try:
            conn.listPath(share, "\\*")
            return True
        except SessionError:
            return False

    def _check_write(self, conn, share):
        test_file = "\\.__smbhunter_wtest"
        try:
            buf = BytesIO(b"")
            conn.putFile(share, test_file, buf.read)
            conn.deleteFile(share, test_file)
            return True
        except Exception:
            return False

    def _count_root_items(self, conn, share):
        try:
            entries = conn.listPath(share, "\\*")
            dirs = files = 0
            for e in entries:
                n = e.get_longname()
                if n in (".", ".."):
                    continue
                if e.is_directory():
                    dirs += 1
                else:
                    files += 1
            return dirs, files
        except Exception:
            return 0, 0

    # ── Recon mode ─────────────────────────────────────────────────────────

    def _score_share(self, name, remark, readable, writable, dirs, files):
        score = 0
        name_l = name.lower()

        if name_l in INTERESTING_SHARE_NAMES:
            score += 30
        for kw in ("backup", "password", "secret", "cred", "admin", "key",
                    "deploy", "script", "finance", "hr", "payroll", "vpn",
                    "private", "confidential"):
            if kw in name_l:
                score += 20
                break

        if writable:
            score += 25
        if readable:
            score += 10
        if files > 0:
            score += min(files, 20)
        if dirs > 0:
            score += min(dirs * 2, 20)

        remark_l = (remark or "").lower()
        for kw in ("backup", "deploy", "admin", "user", "script", "data",
                    "share", "home"):
            if kw in remark_l:
                score += 10
                break

        if name_l in ("c$", "admin$"):
            score += 15

        return score

    def recon_host(self, host):
        print_host_header(host)
        log.info("Recon: %s", host)
        conn = self.connect(host)
        if not conn:
            self._add_error(host, "", "connection failed")
            return

        try:
            signing = conn.isSigningRequired()
            print_signing(host, signing)
            self._inc_stat("signing_required" if signing else "signing_not_required")
        except Exception:
            pass

        try:
            hostname = conn.getServerName()
            domain = conn.getServerDNSDomainName()
            os_ver = conn.getServerOS()
        except Exception:
            hostname = domain = os_ver = ""

        if hostname or os_ver:
            info_parts = []
            if hostname:
                info_parts.append(hostname)
            if domain:
                info_parts.append(domain)
            if os_ver:
                info_parts.append(os_ver)
            print(f"  {' | '.join(info_parts)}", flush=True)

        raw_shares = self.list_shares(conn)
        scored = []

        for share_info in raw_shares:
            name = share_info["name"]
            remark = share_info["remark"]
            readable = self.can_read(conn, name)
            writable = False
            dirs = files = 0

            if readable:
                self._inc_stat("readable_shares")
                if getattr(self.args, "write_check", False):
                    writable = self._check_write(conn, name)
                    if writable:
                        self._inc_stat("writable_shares")
                dirs, files = self._count_root_items(conn, name)
            else:
                self._inc_stat("unreadable_shares")

            score = self._score_share(name, remark, readable, writable, dirs, files)
            entry = {
                "host": host,
                "hostname": hostname,
                "share": name,
                "remark": remark,
                "readable": readable,
                "writable": writable,
                "dirs": dirs,
                "files": files,
                "score": score,
            }
            scored.append(entry)

        scored.sort(key=lambda x: x["score"], reverse=True)
        for s in scored:
            print_recon_share(s)

        with self._lock:
            self._recon_results.extend(scored)

        try:
            conn.logoff()
        except Exception:
            pass

    # ── Directory spider ────────────────────────────────────────────────────

    def spider_dir(self, conn, host, share, path, depth):
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
                    {"tier": t, "line": l, "line_num": ln, "pattern": m}
                    for t, m, ln, l in content_hits
                ],
            }

            dedup_key = (host, name, size,
                         int(mtime.timestamp()) if mtime else 0)
            if dedup_key in self._seen_files:
                self._inc_stat("deduped_files")
                continue
            self._seen_files.add(dedup_key)

            self._add_result(finding)
            log.info("%s [%s] %s — %s (%s)", host, share, full_path, tier,
                     f"{len(content_hits)} content hits" if content_hits else "filename/ext only")
            print_finding(host, share, full_path, tier, size, mtime, content_hits)

            if getattr(self.args, "loot", None) and tier == CRITICAL and size and size > 0:
                self._loot_file(conn, share, full_path, host, name)

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
            return match_content(text, self._extra_patterns)
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

    # ── Loot download ──────────────────────────────────────────────────────

    def _loot_file(self, conn, share, path, host, filename):
        loot_base = self.args.loot
        safe_host = host.replace(":", "_")
        rel_dir = os.path.dirname(path.replace("\\", os.sep).lstrip(os.sep))
        full_dir = os.path.join(loot_base, safe_host, share, rel_dir)
        os.makedirs(full_dir, exist_ok=True)
        local_path = os.path.join(full_dir, filename)
        try:
            with open(local_path, "wb") as f:
                conn.getFile(share, path, f.write)
            log.info("Looted: %s\\%s -> %s", share, path, local_path)
            print_loot(local_path)
        except Exception as e:
            log.warning("Loot failed for %s\\%s: %s", share, path, e)

    # ── Per-host entry point ────────────────────────────────────────────────

    def hunt_host(self, host):
        print_host_header(host)
        log.info("Connecting to %s", host)
        conn = self.connect(host)
        if not conn:
            self._add_error(host, "", "initial connection failed")
            return

        try:
            signing = conn.isSigningRequired()
            print_signing(host, signing)
            self._inc_stat("signing_required" if signing else "signing_not_required")
        except Exception:
            pass

        raw_shares = self.list_shares(conn)
        share_names = [s["name"] for s in raw_shares]

        if hasattr(self.args, "shares") and self.args.shares:
            allowed = {s.strip().lower() for s in self.args.shares.split(",")}
            share_names = [s for s in share_names if s.lower() in allowed]

        for share in share_names:
            if not self.can_read(conn, share):
                self._inc_stat("unreadable_shares")
                continue

            writable = False
            if getattr(self.args, "write_check", False):
                writable = self._check_write(conn, share)
                if writable:
                    self._inc_stat("writable_shares")

            self._inc_stat("readable_shares")
            print_share(share, writable=writable,
                        show_access=getattr(self.args, "write_check", False))

            if share.upper() in ("NETLOGON", "SYSVOL"):
                print_share_warning(share, "login scripts likely contain credentials")

            if writable:
                print_share_warning(share, "WRITABLE", critical=True)

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

    # ── Report flushing ────────────────────────────────────────────────────

    def flush_reports(self):
        from smbhunter.output import write_json_report, write_csv_report
        if self.args.output:
            write_json_report(self.args.output, self.args, self.stats,
                              self.results, self.errors)
        if getattr(self.args, "csv", None):
            write_csv_report(self.args.csv, self.results)

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
        hosts = self._expand_targets()

        if self.args.output:
            self._jsonl_path = self.args.output + "l"

        recon_mode = getattr(self.args, "recon", False)

        log.info("Targets: %d, mode=%s, content=%s, min_tier=%s, depth=%d",
                 len(hosts), "recon" if recon_mode else "hunt",
                 self.args.content, self.min_tier, self.args.depth)
        print_banner(len(hosts), self.args)
        start = time.time()

        worker = self.recon_host if recon_mode else self.hunt_host

        if self.args.threads > 1 and len(hosts) > 1:
            with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
                futures = {ex.submit(worker, h): h for h in hosts}
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        host = futures[f]
                        self._add_error(host, "", str(e))
                        print(f"  [-] {host}: {e}", flush=True)
        else:
            for host in hosts:
                worker(host)

        elapsed = time.time() - start
        log.info("Scan complete in %.1fs — %d findings, %d errors",
                 elapsed, len(self.results), len(self.errors))

        if recon_mode:
            from smbhunter.output import print_recon_summary
            print_recon_summary(elapsed, self.stats, self._recon_results, self.errors)
            if self.args.output:
                from smbhunter.output import write_json_recon_report
                write_json_recon_report(self.args.output, self.args,
                                        self.stats, self._recon_results, self.errors)
            if getattr(self.args, "csv", None):
                from smbhunter.output import write_csv_recon_report
                write_csv_recon_report(self.args.csv, self._recon_results)
        else:
            print_summary(elapsed, self.stats, self.results, self.errors, self.args)
            self.flush_reports()
