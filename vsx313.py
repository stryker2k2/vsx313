#!/usr/bin/env python3
"""
Read-only IOC checker for the backdoored Claude Code VS Code extension 2.1.313.

Source: https://phorion.io/blog/offical-claude-code-vsx-compromise/

Checks (nothing is modified, nothing is sent over the network):
  - Installed / cached extension builds of anthropic.claude-code-2.1.313
  - SHA-256 of every installed anthropic.claude-code extension.js
  - ~/.ssh/authorized_keys for the svc-telemetry key (comment and fingerprint)
  - Dropped tunnel keys and scripts (/tmp/.stk_*, ~/.config/.smt, .smtk, ...)
  - macOS LaunchAgent com.apple.sysmond, Linux @reboot cron, Windows SysMon task
  - Running ssh/autossh reverse tunnels and live connections to the C2
  - sshd logs for logins with the attacker key or from localhost

Usage:
  python3 vsx313.py               # current user
  sudo python3 vsx313.py          # all users + system logs (Linux/macOS)
  python3 vsx313.py --deep-logs   # also search macOS unified log (slow)
  py vsx313.py                    # Windows; from an Administrator prompt for all
                                  # users, SYSTEM tasks and the OpenSSH event log

Exit code: 0 clean, 1 warnings only, 2 indicators found.
"""

import argparse
import base64
import glob
import gzip
import hashlib
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# IOCs, assembled so this file itself does not trip naive scanners.
C2_IP = ".".join(["134", "209", "82", "225"])
BAD_VERSION = "2.1.313"
BAD_EXTENSION_SHA256 = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"
LOGIN_KEY_COMMENT = "svc-telemetry"
LOGIN_KEY_FP = "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk"
TUNNEL_KEY_COMMENT = "svc-telemetry-tun"
TUNNEL_KEY_FP = "SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ"
BAD_FPS = {LOGIN_KEY_FP: LOGIN_KEY_COMMENT, TUNNEL_KEY_FP: TUNNEL_KEY_COMMENT}
CONTENT_MARKERS = [C2_IP, LOGIN_KEY_COMMENT, "com.apple.sysmond", ".config/.smtk", ":8099/beacon"]
# Matched against command lines with backslashes normalized to forward slashes.
PROC_MARKERS = [C2_IP, "*:0:localhost:22", "/.stk_", ".config/.smtk", ".config/.smt", ".config/smtk", "smt.cmd"]

SYSTEM = platform.system()  # Linux, Darwin, Windows

HIT, WARN, INFO, OK = "HIT", "WARN", "INFO", "OK"
COLORS = {HIT: "\033[1;31m", WARN: "\033[1;33m", INFO: "\033[36m", OK: "\033[32m"}
results = []
use_color = sys.stdout.isatty()


def report(level, check, msg):
    results.append((level, check, msg))
    tag = f"[{level}]"
    if use_color:
        tag = f"{COLORS[level]}{tag}\033[0m"
    print(f"{tag:>6} {check}: {msg}")


def run(cmd, timeout=60):
    """Run a command, return (rc, stdout). rc is None if the binary is missing."""
    exe = shutil.which(cmd[0])  # full path, so Windows .cmd shims like npm.cmd launch
    if not exe:
        return None, ""
    try:
        p = subprocess.run([exe] + cmd[1:], capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None, ""


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def is_admin():
    if SYSTEM == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (ImportError, AttributeError, OSError):
            return False
    return os.geteuid() == 0


ELEVATE_HINT = "run as Administrator" if SYSTEM == "Windows" else "run with sudo"
PROGRAMDATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def private_key_fingerprint(path):
    """Fingerprint of the public half embedded in an unencrypted OpenSSH private key."""
    text = read_text(path)
    if not text or "OPENSSH PRIVATE KEY" not in text:
        return None
    body = "".join(l for l in text.splitlines() if l and not l.startswith("-----"))
    try:
        data = base64.b64decode(body)
        magic = b"openssh-key-v1\0"
        if not data.startswith(magic):
            return None
        off = len(magic)

        def read_str():
            nonlocal off
            (n,) = struct.unpack(">I", data[off:off + 4])
            off += 4
            s = data[off:off + n]
            off += n
            return s

        read_str(), read_str(), read_str()  # cipher, kdf, kdf options
        off += 4  # number of keys
        return fingerprint(read_str())
    except (ValueError, struct.error):
        return None


def user_homes():
    """Current user's home, or every account's home when running as root / Administrator."""
    homes = {Path.home()}
    if not is_admin():
        return sorted(homes)
    if SYSTEM == "Windows":
        users = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
        skip = {"public", "default", "default user", "all users"}
        for p in users.glob("*"):
            if p.is_dir() and not p.is_symlink() and p.name.lower() not in skip:
                homes.add(p)
    else:
        import pwd
        for pw in pwd.getpwall():
            p = Path(pw.pw_dir)
            if p != Path("/") and p.is_dir() and ((p / ".ssh").exists() or (p / ".config").exists()):
                homes.add(p)
    return sorted(homes)


# ---------------------------------------------------------------- checks

def check_extensions(homes):
    name = "extension"
    found_any = False
    roots = []
    for home in homes:
        roots += glob.glob(str(home / ".*" / "extensions" / "anthropic.claude-code-*"))
        for cache in ("Library/Application Support/*/CachedExtensionVSIXs",
                      ".config/*/CachedExtensionVSIXs",
                      "AppData/Roaming/*/CachedExtensionVSIXs"):
            roots += glob.glob(str(home / cache / f"anthropic.claude-code-{BAD_VERSION}*"))

    for root in sorted(set(roots)):
        found_any = True
        if BAD_VERSION in Path(root).name:
            report(HIT, name, f"compromised version {BAD_VERSION} present: {root}")
        for js in glob.glob(os.path.join(root, "**", "extension.js"), recursive=True):
            try:
                digest = sha256_file(js)
                content = Path(js).read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                report(WARN, name, f"cannot read {js}: {e}")
                continue
            if digest == BAD_EXTENSION_SHA256:
                report(HIT, name, f"backdoored extension.js hash match: {js}")
            markers = [m for m in CONTENT_MARKERS if m in content]
            if markers:
                report(HIT, name, f"{js} contains IOC strings: {', '.join(markers)}")
    if not found_any:
        report(OK, name, "no anthropic.claude-code extension directories found")
    elif not any(r[1] == name and r[0] == HIT for r in results):
        report(OK, name, f"anthropic.claude-code installs found, none are {BAD_VERSION} or backdoored")


def check_npm():
    name = "npm"
    roots = {"/usr/local/lib/node_modules", "/usr/lib/node_modules", "/opt/homebrew/lib/node_modules",
             str(Path.home() / ".npm-global/lib/node_modules"),
             str(Path.home() / "AppData/Roaming/npm/node_modules")}
    rc, out = run(["npm", "root", "-g"], timeout=20)
    if rc == 0 and out.strip():
        roots.add(out.strip())
    seen = False
    for r in roots:
        pkg = Path(r) / "@anthropic-ai" / "claude-code"
        text = read_text(pkg / "package.json")
        if text is None:
            continue
        seen = True
        m = re.search(r'"version"\s*:\s*"([^"]+)"', text)
        ver = m.group(1) if m else "?"
        if ver == BAD_VERSION:
            report(WARN, name, f"pulled npm version {BAD_VERSION} installed at {pkg}; upgrade it")
        for js in glob.glob(str(pkg / "*.js")):
            content = read_text(js) or ""
            markers = [m for m in CONTENT_MARKERS if m in content]
            if markers:
                report(HIT, name, f"{js} contains IOC strings: {', '.join(markers)}")
    if not seen:
        report(OK, name, "no global @anthropic-ai/claude-code install found")
    elif not any(r[1] == name for r in results):
        report(OK, name, f"global @anthropic-ai/claude-code install is not {BAD_VERSION}")


def check_authorized_keys(homes):
    name = "authorized_keys"
    files = [home / ".ssh" / f for home in homes for f in ("authorized_keys", "authorized_keys2")]
    if SYSTEM == "Windows":
        # Windows OpenSSH reads this instead of ~/.ssh/authorized_keys for admin accounts.
        files.append(PROGRAMDATA / "ssh" / "administrators_authorized_keys")
    for ak in files:
        text = read_text(ak)
        if text is None:
            continue
        clean = True
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if LOGIN_KEY_COMMENT in line:
                report(HIT, name, f"{ak}:{lineno} has key comment '{LOGIN_KEY_COMMENT}'")
                clean = False
            tokens = line.split()
            for i, tok in enumerate(tokens[:-1]):
                if re.match(r"^(ssh-|ecdsa-|sk-)", tok):
                    try:
                        fp = fingerprint(base64.b64decode(tokens[i + 1]))
                    except ValueError:
                        continue
                    if fp in BAD_FPS:
                        report(HIT, name, f"{ak}:{lineno} attacker key fingerprint {fp}")
                        clean = False
                    break
        if clean:
            report(OK, name, f"{ak} clean")


def tmp_dirs(homes):
    dirs = {tempfile.gettempdir(), "/tmp", "/var/tmp", os.environ.get("TMPDIR", ""), os.environ.get("TEMP", "")}
    if SYSTEM == "Darwin":
        dirs.update(glob.glob("/var/folders/*/*/T"))
    elif SYSTEM == "Windows":
        dirs.update(str(h / "AppData" / "Local" / "Temp") for h in homes)
    return [d for d in dirs if d and os.path.isdir(d)]


def stk_suffix(seed):
    """The malware's .stk_ name suffix. MD5 is only used to match its naming, not for security,
    which FIPS-mode builds need told explicitly (and may still refuse)."""
    try:
        try:
            h = hashlib.md5(seed.encode(), usedforsecurity=False)
        except TypeError:  # Python < 3.9
            h = hashlib.md5(seed.encode())
        return h.hexdigest()[:10]
    except ValueError:
        return None  # the .stk_* glob still catches the file


def check_dropped_files(homes):
    name = "files"
    hits_before = len(results)
    host = socket.gethostname()

    startup = Path("Microsoft/Windows/Start Menu/Programs/Startup/sysmon.cmd")
    tmps = tmp_dirs(homes)
    candidates = []
    for d in tmps:
        candidates += glob.glob(os.path.join(d, ".stk_*"))
    for home in homes:
        expected = stk_suffix(host + str(home))
        if expected:
            for d in tmps:
                candidates.append(os.path.join(d, f".stk_{expected}"))
        cfg = home / ".config"
        candidates += [str(cfg / f) for f in (".smt", ".smtk", "smt.cmd", "smtk")]
        candidates.append(str(home / "Library/LaunchAgents/com.apple.sysmond.plist"))
        candidates.append(str(home / "AppData/Roaming" / startup))
    if SYSTEM == "Windows":
        if os.environ.get("APPDATA"):
            candidates.append(str(Path(os.environ["APPDATA"]) / startup))
        candidates.append(str(PROGRAMDATA / startup))  # all-users Startup folder

    for path in sorted(set(candidates)):
        if not os.path.exists(path):
            continue
        detail = ""
        fp = private_key_fingerprint(path)
        if fp:
            detail = f" (key {fp}{', ATTACKER TUNNEL KEY' if fp in BAD_FPS else ''})"
        report(HIT, name, f"{path}{detail}")
    if len(results) == hits_before:
        report(OK, name, "no dropped keys, scripts, or LaunchAgent found")


def check_cron():
    if SYSTEM != "Linux" and SYSTEM != "Darwin":
        return
    name = "crontab"
    rc, out = run(["crontab", "-l"])
    if rc is None:
        report(INFO, name, "crontab not available")
        return
    bad = [l for l in out.splitlines() if ".smt" in l or C2_IP in l]
    for l in bad:
        report(HIT, name, f"malicious entry: {l.strip()}")
    spool = glob.glob("/var/spool/cron/crontabs/*") + glob.glob("/var/spool/cron/*")
    for f in spool:
        text = read_text(f) or ""
        for l in text.splitlines():
            if ".smt" in l or C2_IP in l:
                report(HIT, name, f"{f}: {l.strip()}")
                bad.append(l)
    if not bad:
        report(OK, name, "no .smt / C2 entries" + ("" if is_admin() else " (current user only)"))


def check_launchd(homes):
    if SYSTEM != "Darwin":
        return
    import plistlib
    name = "launchd"
    hits_before = len(results)
    for home in homes:
        # Apple ships nothing in per-user LaunchAgents, so a com.apple.* label there is a disguise.
        for plist in sorted((home / "Library" / "LaunchAgents").glob("*.plist")):
            try:
                with open(plist, "rb") as f:
                    data = plistlib.load(f)
            except (OSError, plistlib.InvalidFileException, ValueError) as e:
                report(INFO, name, f"cannot parse {plist}: {e}")
                continue
            label = str(data.get("Label", ""))
            argv = " ".join(map(str, [data.get("Program", "")] + list(data.get("ProgramArguments", []))))
            if ".config/.smt" in argv or C2_IP in argv:
                report(HIT, name, f"{plist} (label {label}) runs the payload: {argv.strip()}")
            elif label.startswith("com.apple."):
                report(WARN, name, f"{plist} uses Apple label '{label}' in a user LaunchAgent: {argv.strip()}")
            elif re.search(r"/bin/(ba|z)?sh\b.*/\.[^/\s]+", argv):
                report(WARN, name, f"{plist} (label {label}) runs a shell on a hidden file: {argv.strip()}")

        # As root, plain `launchctl list` shows the system domain, not the user's GUI session.
        uid = home.stat().st_uid
        cmd = ["launchctl", "print", f"gui/{uid}/com.apple.sysmond"] if is_admin() else ["launchctl", "list"]
        rc, out = run(cmd)
        if rc == 0 and "com.apple.sysmond" in out:
            report(HIT, name, f"LaunchAgent com.apple.sysmond is loaded for uid {uid}")
    if len(results) == hits_before:
        report(OK, name, "no suspicious user LaunchAgents, com.apple.sysmond not loaded")


def check_windows_tasks():
    if SYSTEM != "Windows":
        return
    name = "schtasks"
    rc, out = run(["schtasks", "/query", "/tn", "SysMon", "/v", "/fo", "LIST"])
    if rc is None:
        report(INFO, name, "schtasks not available")
    elif rc == 0:
        norm = out.replace("\\", "/")
        if any(m in norm for m in (".config/smt", "smt.cmd", "/bin/sh", C2_IP)):
            report(HIT, name, "malicious scheduled task 'SysMon':\n" + out.strip())
        else:
            report(WARN, name, "scheduled task 'SysMon' exists but does not reference the payload; verify it:\n"
                   + out.strip())
    else:
        report(OK, name, "no 'SysMon' scheduled task" + ("" if is_admin() else f" ({ELEVATE_HINT} to be sure)"))


def list_processes():
    """(pid, ppid, command line) for every process."""
    procs = []
    if SYSTEM == "Linux":
        for d in glob.glob("/proc/[0-9]*"):
            try:
                raw = Path(d, "cmdline").read_bytes()
            except OSError:
                continue
            m = re.search(r"\) \S+ (\d+)", read_text(f"{d}/stat") or "")
            procs.append((d.split("/")[-1], m.group(1) if m else "0",
                          raw.replace(b"\0", b" ").decode(errors="replace").strip()))
    elif SYSTEM == "Darwin":
        _, out = run(["ps", "-axww", "-o", "pid=,ppid=,command="])
        for l in out.splitlines():
            parts = l.split(None, 2)
            if len(parts) == 3:
                procs.append(tuple(parts))
    else:
        _, out = run(["powershell", "-NoProfile", "-Command",
                      "Get-CimInstance Win32_Process | ForEach-Object "
                      "{ \"$($_.ProcessId)`t$($_.ParentProcessId)`t$($_.CommandLine)\" }"])
        for l in out.splitlines():
            parts = l.split("\t", 2)
            if len(parts) == 3:
                procs.append(tuple(parts))
    return procs


def own_ancestry(procs):
    """PIDs of this checker and its parents, so the shell that launched it is not flagged."""
    parent = {p[0]: p[1] for p in procs}
    pids, pid = set(), str(os.getpid())
    while pid not in ("0", "1") and pid not in pids:
        pids.add(pid)
        pid = parent.get(pid, "0")
    return pids


def check_processes():
    name = "process"
    procs = list_processes()
    mine = own_ancestry(procs)
    bad = 0
    for pid, _, cmd in procs:
        if pid in mine or not cmd:
            continue
        norm = cmd.replace("\\", "/")
        markers = [m for m in PROC_MARKERS if m in norm]
        if markers:
            report(HIT, name, f"pid {pid}: {cmd[:300]}")
            bad += 1
    if not bad:
        report(OK, name, "no tunnel / retry-loop processes")


def ipv4_proc_hex(ip):
    return "%08X" % struct.unpack("<I", socket.inet_aton(ip))[0]


def check_connections():
    name = "network"
    found = []
    if SYSTEM == "Linux":
        target = ipv4_proc_hex(C2_IP)
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            text = read_text(f) or ""
            for l in text.splitlines()[1:]:
                parts = l.split()
                if len(parts) > 2 and parts[2].split(":")[0].upper().endswith(target):
                    port = int(parts[2].split(":")[1], 16)
                    found.append(f"{f}: connection to {C2_IP}:{port}")
    else:
        _, out = run(["netstat", "-an"])
        found = [l.strip() for l in out.splitlines() if C2_IP in l]
    for f in found:
        report(HIT, name, f)
    if not found:
        report(OK, name, f"no live connections to {C2_IP}")


def scan_log_lines(lines, source):
    name = "sshd-log"
    n = 0
    for l in lines:
        if any(fp in l for fp in BAD_FPS):
            report(HIT, name, f"{source}: {l.strip()[:300]}")
            n += 1
        elif "Accepted publickey" in l and re.search(r"from (127\.0\.0\.1|::1) ", l):
            report(WARN, name, f"{source}: localhost key login (verify it is yours): {l.strip()[:300]}")
            n += 1
    return n


def check_logs(deep):
    name = "sshd-log"
    searched = False
    if SYSTEM == "Linux":
        for f in sorted(glob.glob("/var/log/auth.log*") + glob.glob("/var/log/secure*")):
            try:
                opener = gzip.open if f.endswith(".gz") else open
                with opener(f, "rt", errors="replace") as fh:
                    scan_log_lines(fh, f)
                searched = True
            except PermissionError:
                report(INFO, name, f"no permission to read {f} (run with sudo)")
            except OSError:
                pass
        for comm in ("sshd", "sshd-session"):
            rc, out = run(["journalctl", "-q", "--no-pager", f"_COMM={comm}"], timeout=120)
            if rc == 0:
                searched = True
                scan_log_lines(out.splitlines(), f"journalctl _COMM={comm}")
    elif SYSTEM == "Darwin":
        if deep:
            rc, out = run(["log", "show", "--style", "syslog", "--last", "30d", "--predicate",
                           'process == "sshd" OR process == "sshd-session"'], timeout=600)
            if rc == 0:
                searched = True
                scan_log_lines(out.splitlines(), "unified log")
        else:
            report(INFO, name, "macOS unified log skipped; rerun with --deep-logs to search it")
            return
    elif SYSTEM == "Windows":
        rc, out = run(["powershell", "-NoProfile", "-Command",
                       "try { Get-WinEvent -LogName 'OpenSSH/Operational' -ErrorAction Stop | "
                       "ForEach-Object { $_.Message } } catch { "
                       "if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { exit 0 } else { exit 1 } }"],
                      timeout=120)
        if rc == 0:
            searched = True
            scan_log_lines(out.splitlines(), "OpenSSH/Operational")
        elif rc is not None and not is_admin():
            report(INFO, name, f"could not read the OpenSSH/Operational event log ({ELEVATE_HINT})")
        # Used instead of the event log when sshd_config sets SyslogFacility LOCAL0.
        for f in sorted(glob.glob(str(PROGRAMDATA / "ssh" / "logs" / "sshd*.log"))):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    scan_log_lines(fh, f)
                searched = True
            except PermissionError:
                report(INFO, name, f"no permission to read {f} ({ELEVATE_HINT})")
            except OSError:
                pass
    if not searched:
        report(INFO, name, "no sshd logs could be searched")
    elif not any(r[1] == name and r[0] in (HIT, WARN) for r in results):
        report(OK, name, "no attacker-key or localhost key logins found")


def proc_addr(hexaddr):
    """Decode an address from /proc/net/tcp{,6} into (ip, port)."""
    ip_hex, port_hex = hexaddr.split(":")
    raw = bytes.fromhex(ip_hex)
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    if len(raw) == 4:
        ip = socket.inet_ntop(socket.AF_INET, raw)
    elif raw.startswith(b"\0" * 10 + b"\xff\xff"):
        ip = socket.inet_ntop(socket.AF_INET, raw[12:])
    else:
        ip = socket.inet_ntop(socket.AF_INET6, raw)
    return ip, int(port_hex, 16)


def ssh_sockets():
    """(state, local, peer) for TCP sockets on local port 22. Passive: never connects,
    since a probe would start sshd on socket-activated hosts (systemd ssh.socket)."""
    socks = []
    if SYSTEM == "Linux":
        states = {"0A": "LISTEN", "01": "ESTABLISHED"}
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            for l in (read_text(f) or "").splitlines()[1:]:
                parts = l.split()
                if len(parts) < 4 or parts[3] not in states:
                    continue
                local, peer = proc_addr(parts[1]), proc_addr(parts[2])
                if local[1] == 22:
                    socks.append((states[parts[3]], f"{local[0]}:{local[1]}", f"{peer[0]}:{peer[1]}"))
    else:
        _, out = run(["netstat", "-an"])
        for l in out.splitlines():
            tokens = l.split()
            state = next((s for s in ("LISTEN", "LISTENING", "ESTABLISHED") if s in tokens), None)
            idx = 1 if SYSTEM == "Windows" else 3
            if not state or len(tokens) <= idx + 1:
                continue
            local, peer = tokens[idx], tokens[idx + 1]
            if re.search(r"[.:]22$", local):
                socks.append(("LISTEN" if state.startswith("LISTEN") else state, local, peer))
    return socks


def check_sshd():
    name = "sshd"
    socks = ssh_sockets()
    listening = sorted({s[1] for s in socks if s[0] == "LISTEN"})
    sessions = [s for s in socks if s[0] == "ESTABLISHED"]
    if listening:
        report(INFO, name, f"port 22 open on {', '.join(listening)}; confirm SSH / Remote Login is meant to be on")
    else:
        report(OK, name, "nothing listening on port 22")
    for _, local, peer in sessions:
        if re.match(r"^(127\.|::1|\[::1\])", peer):
            report(WARN, name, f"inbound SSH session from localhost {peer}: the tunnel login path, verify it")
        else:
            report(INFO, name, f"inbound SSH session from {peer}")
    if listening and not sessions:
        report(OK, name, "no active inbound SSH sessions")
    if SYSTEM == "Windows":
        # The payload installs OpenSSH Server via PowerShell if it is missing.
        rc, out = run(["powershell", "-NoProfile", "-Command",
                       "Get-Service sshd -ErrorAction SilentlyContinue | "
                       "ForEach-Object { \"$($_.Status) $($_.StartType)\" }"])
        if rc == 0 and out.strip():
            report(INFO, name, f"Windows OpenSSH Server service installed ({out.strip()}); "
                   "if nobody installed it on purpose, treat that as suspicious")
        elif rc == 0:
            report(OK, name, "Windows OpenSSH Server service not installed")


# ---------------------------------------------------------------- main

def main():
    global use_color
    ap = argparse.ArgumentParser(description="Check for Claude Code VSX 2.1.313 compromise IOCs (read-only).")
    ap.add_argument("--deep-logs", action="store_true", help="search the macOS unified log (slow)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    use_color = use_color and not args.no_color
    if use_color and SYSTEM == "Windows":
        os.system("")  # turns on ANSI escape handling in the classic Windows console

    homes = user_homes()
    print(f"Claude Code VSX {BAD_VERSION} IOC check on {socket.gethostname()} ({SYSTEM})")
    print(f"Homes scanned: {', '.join(map(str, homes))}\n")

    check_extensions(homes)
    check_npm()
    check_authorized_keys(homes)
    check_dropped_files(homes)
    check_cron()
    check_launchd(homes)
    check_windows_tasks()
    check_processes()
    check_connections()
    check_sshd()
    check_logs(args.deep_logs)

    hits = sum(1 for r in results if r[0] == HIT)
    warns = sum(1 for r in results if r[0] == WARN)
    print(f"\nSummary: {hits} indicator(s), {warns} warning(s)")
    if hits:
        print("Likely compromised. Uninstalling the extension does NOT remove the backdoor. See remediation:\n"
              "  https://phorion.io/blog/offical-claude-code-vsx-compromise/\n"
              "Rotate any credentials reachable by this user, especially *KEY*/*TOKEN*/*SECRET*/*PASS*/AWS/GCP env vars.")
        return 2
    return 1 if warns else 0


if __name__ == "__main__":
    sys.exit(main())
