#!/usr/bin/env python3
"""The guard rails around the AI investigator. Everything an AI says or sees passes through here.

Two jobs, both deliberately boring and fully testable:

1. REDACTION: strip what must never leave this laptop (secrets, private keys, your username, hostname, home path,
   email addresses, MAC addresses) from the evidence BEFORE it is shown in the preview or sent anywhere.
2. COMMAND SAFETY: the AI may suggest commands to run. A suggestion is only ever DISPLAYED unless it passes a strict
   allow-list of read-only programs with checked arguments, and even then it runs only when YOU press a button, never
   through a shell, never with sudo, with a timeout and capped, redacted output. Anything else is shown as "not run by
   LinuxGuardian: understand it before you try it", with a risk flag when it would change things.

The model's output is treated as untrusted text (it was reading attacker-controlled evidence): it can't start anything,
acknowledge or silence an incident, edit the allow-list, or touch your files.
"""
from __future__ import annotations

import os
import pwd
import re
import shlex
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

try:  # shared secret scrubber used by the sensors
    from sensors import redact_args
except Exception:  # noqa: BLE001 - keep this module importable on its own
    def redact_args(text: str) -> str:
        return text

OUTPUT_LIMIT = 20_000
RUN_TIMEOUT = 15


# ================================================================== redaction
@dataclass
class Redaction:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        if not self.counts:
            return "Nothing needed removing."
        return "Removed or masked: " + ", ".join(f"{n} {k}" for k, n in sorted(self.counts.items()))


def _identity() -> tuple[str, str, str]:
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = os.environ.get("USER", "")
    home = os.environ.get("LG_SENSOR_HOME") or os.environ.get("HOME") or str(Path.home())
    return user, home, socket.gethostname()


PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
BLOB = re.compile(r"\b[A-Za-z0-9+/_-]{48,}={0,2}\b")
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{16}$")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def redact(text: str, level: str = "standard") -> Redaction:
    """standard: secrets, keys, identity. strict: also masks the host part of IP addresses and flattens home paths."""
    counts: dict[str, int] = {}

    def bump(kind: str, n: int = 1) -> None:
        counts[kind] = counts.get(kind, 0) + n

    user, home, host = _identity()
    scrubbed = redact_args(text)
    if scrubbed != text:
        bump("secret value(s)", len(re.findall(r"\[redacted\]", scrubbed)) - len(re.findall(r"\[redacted\]", text)))
    text = scrubbed
    text, n = PRIVATE_KEY.subn("[private key removed]", text)
    if n:
        bump("private key block(s)", n)
    text, n = EMAIL.subn("EMAIL", text)
    if n:
        bump("email address(es)", n)
    text, n = MAC.subn("MAC", text)
    if n:
        bump("MAC address(es)", n)

    def blob(m: re.Match) -> str:
        if HEX64.match(m.group(0)):
            return m.group(0)                                    # file hashes are evidence, keep them
        bump("long token-like string(s)")
        return "[long-token]"

    text = BLOB.sub(blob, text)
    if home and home != "/":
        pat = re.escape(home.rstrip("/")) + r"(?![\w.-])"            # /home/alice, but never the front of /home/alicette
        text, n = re.subn(pat, "~", text)
        if n:
            bump("home path(s)", n)
    if user and len(user) > 1:
        n = len(re.findall(rf"(?<![\w.-]){re.escape(user)}(?![\w.-])", text))
        if n:
            text = re.sub(rf"(?<![\w.-]){re.escape(user)}(?![\w.-])", "USER", text)
            bump("username(s)", n)
    if host and len(host) > 1:
        n = len(re.findall(rf"(?<![\w.-]){re.escape(host)}(?![\w.-])", text))
        if n:
            text = re.sub(rf"(?<![\w.-]){re.escape(host)}(?![\w.-])", "HOST", text)
            bump("hostname(s)", n)
    if level == "strict":
        def mask(m: re.Match) -> str:
            a, b, c, d = (int(x) for x in m.groups())
            if a in (127, 0) or (a == 10) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
                return m.group(0)                                # private/loopback addresses carry no identity
            bump("public IP address(es) generalised")
            return f"{a}.{b}.x.x"

        text = IPV4.sub(mask, text)
        text, n = re.subn(r"~/[^\s:]*/([^/\s:]+)", r"~/…/\1", text)
        if n:
            bump("deep home path(s) flattened", n)
    return Redaction(text, counts)


# ============================================================ command safety
SHELL_SYNTAX = re.compile(r"[;&|<>`$\\\n\r(){}*?!\[\]#]")
RISKY_WORDS = re.compile(r"\b(rm|rmdir|mv|cp|dd|mkfs|shred|kill|killall|pkill|chmod|chown|chattr|sudo|su|doas|passwd|usermod|userdel|useradd|"
                         r"curl|wget|nc|ncat|socat|ssh|scp|rsync|python3?|perl|ruby|node|bash|sh|zsh|eval|exec|tee|truncate|ln|crontab\s+-[re]|"
                         r"systemctl\s+(?:stop|start|restart|disable|enable|mask|kill)|iptables|ufw|nft|apt(?:-get)?\s+(?:remove|purge|install))\b", re.I)
SENSITIVE_PATH = re.compile(r"(environ|/shadow|gshadow|\.ssh(?:/(?!config$|known_hosts)|$)|\.gnupg|\.aws|\.netrc|\.git-credentials|\.docker/config|\.kube|"
                            r"\.npmrc|\.pypirc|credentials|secret|token|passw(?!d\b)|\.env\b|\.pem$|id_rsa|id_ed25519|keyring|\.mozilla|\.config/google-chrome|/Cookies)", re.I)
LOG_FILES = {"/var/log/auth.log", "/var/log/syslog", "/var/log/dpkg.log", "/var/log/kern.log", "/var/log/ufw.log"}
READABLE_FILES = {"/etc/passwd", "/etc/group", "/etc/os-release", "/etc/hosts", "/etc/crontab", "/etc/ld.so.preload", "/etc/resolv.conf"} | LOG_FILES
READABLE_PREFIXES = ("/etc/cron.d/", "/etc/systemd/system/", "/etc/xdg/autostart/", "/proc/")
PROC_FILE = re.compile(r"^/proc/(\d+)/(cmdline|status|stat|cgroup|maps|net/tcp|limits|comm)$")
PID = re.compile(r"^\d{1,7}$")


@dataclass
class Verdict:
    runnable: bool
    argv: list[str] = field(default_factory=list)
    risky: bool = False
    reason: str = ""


def _home() -> str:
    return _identity()[1]


def _path_ok(arg: str) -> str:
    """'' if the path argument may be touched, else the reason."""
    if not arg.startswith(("/", "~/")) or ".." in arg.split("/"):
        return "paths must be absolute and free of '..'"
    expanded = arg.replace("~", _home(), 1)
    if SENSITIVE_PATH.search(expanded):
        return "that path can hold secrets"
    return ""


def _flags_only(args: list[str], allowed: set[str]) -> bool:
    return all(a in allowed or re.fullmatch(r"-[A-Za-z]{1,6}", a) and set(a[1:]) <= {x[1:] for x in allowed if len(x) == 2} for a in args if a.startswith("-"))


def check_command(cmd: str) -> Verdict:
    """Decide whether a suggested command may be offered with a 'Run' button. Never raises."""
    cmd = (cmd or "").strip()
    if not cmd or len(cmd) > 300:
        return Verdict(False, reason="empty or too long")
    risky = bool(RISKY_WORDS.search(cmd))
    if SHELL_SYNTAX.search(cmd):
        return Verdict(False, risky=risky or "|" in cmd or ";" in cmd or "&" in cmd, reason="uses shell syntax (pipes, redirects, substitution, wildcards)")
    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError:
        return Verdict(False, reason="can't be parsed")
    if not argv:
        return Verdict(False, reason="empty")
    prog, args = os.path.basename(argv[0]), argv[1:]
    if argv[0] != prog and argv[0] not in ("/usr/bin/" + prog, "/bin/" + prog, "/usr/sbin/" + prog, "/sbin/" + prog):
        return Verdict(False, risky=risky, reason="run programs by name, not by an arbitrary path")
    if prog in ("sudo", "su", "doas", "pkexec"):
        return Verdict(False, risky=True, reason="LinuxGuardian never runs anything with elevated rights")

    def fail(why: str) -> Verdict:
        return Verdict(False, risky=risky, reason=why)

    def ok() -> Verdict:
        return Verdict(True, [prog, *args], risky=False, reason="read-only")

    paths = [a for a in args if a.startswith(("/", "~/"))]
    for a in paths:
        why = _path_ok(a)
        if why:
            return fail(why)

    if prog in ("ls", "stat", "file", "readlink", "sha256sum"):
        if not args or not _flags_only(args, {"-l", "-a", "-h", "-d", "-L", "-f", "-t", "-1", "-i", "-n", "-b"}):
            return fail("only simple flags are allowed")
        if any(not (a.startswith("-") or a.startswith(("/", "~/"))) for a in args):
            return fail("give absolute paths")
        return ok()
    if prog in ("ps", "pstree"):
        return ok() if all(a.startswith("-") or a.isalpha() or PID.match(a) or re.fullmatch(r"[a-z,%]+", a) or re.fullmatch(r"-[a-zA-Z]+", a) for a in args) else fail("unusual arguments")
    if prog == "ss":
        return ok() if args and all(re.fullmatch(r"-[tunlpaHos4605emi]+", a) for a in args) else fail("only listing flags (-tunap) are allowed")
    if prog in ("last", "lastb"):
        return ok() if all(re.fullmatch(r"-(n|F|a|i|w|x|\d+)", a) or PID.match(a) for a in args) else fail("unusual arguments")
    if prog in ("who", "w", "id", "uptime", "uname", "lsmod", "df", "free", "whoami", "hostname"):
        return ok() if all(re.fullmatch(r"-[a-zA-Z]+", a) for a in args) else fail("only simple flags are allowed")
    if prog == "getent":
        return ok() if len(args) >= 1 and args[0] in ("passwd", "group", "hosts") and all(re.fullmatch(r"[\w.-]+", a) for a in args[1:]) else fail("getent passwd|group|hosts only")
    if prog == "systemctl":
        verbs = {"status", "list-units", "list-unit-files", "list-timers", "show", "cat", "is-active", "is-enabled"}
        flags = [a for a in args if a.startswith("-")]
        rest = [a for a in args if not a.startswith("-")]
        if rest and rest[0] in verbs and set(flags) <= {"--user", "--no-pager", "--type=service", "--type=timer", "--state=running", "--all", "-l", "--failed"} and all(re.fullmatch(r"[\w@.:-]+", a) for a in rest):
            return ok()
        return fail("only read-only systemctl verbs (status, list-units, cat, ...)")
    if prog == "journalctl":
        bad = re.compile(r"--(vacuum|rotate|flush|sync|setup|relinquish|smart|update-catalog|verify|rotate)|--output-fields", re.I)
        if any(bad.search(a) for a in args):
            return fail("that journalctl option changes things")
        okflags = all(re.fullmatch(r"--no-pager|-n|\d+|-u|[\w@.-]+\.(service|timer|socket)|--since=?.*|-t|[\w.-]+|--user|-b|-p|\w+|-o|json|short|cat|_PID=\d+|_COMM=[\w.-]+|_UID=\d+", a) for a in args)
        return ok() if okflags and not any(("/" in a) for a in args) else fail("unusual journalctl arguments")
    if prog == "lsof":
        return ok() if args and all(re.fullmatch(r"-[nPlt]+|-p|-i|-u|\d{1,7}|[\w.:@-]+", a) for a in args) and "-c" not in args else fail("only listing flags")
    if prog == "dpkg":
        return ok() if args and args[0] in ("-S", "-L", "-s", "-l", "--search", "--listfiles", "--status", "--list") and all(not a.startswith("-") for a in args[1:]) else fail("dpkg -S/-L/-s/-l only")
    if prog == "apt-cache":
        return ok() if args and args[0] in ("policy", "show", "depends", "rdepends", "search") and all(re.fullmatch(r"[\w.+:-]+", a) for a in args[1:]) else fail("apt-cache policy/show only")
    if prog == "crontab":
        return ok() if args == ["-l"] else fail("crontab -l only")
    if prog == "ip":
        return ok() if args and args[0] in ("addr", "a", "route", "r", "link", "l", "neigh", "n") and all(a in ("show", "-s", "-4", "-6", "-br", "-c", "dev") or re.fullmatch(r"[\w.-]+", a) for a in args[1:]) and not any(a in ("add", "del", "delete", "flush", "set", "replace", "change") for a in args) else fail("ip ... show only")
    if prog in ("cat", "head", "tail", "grep"):
        files = [a for a in args if a.startswith(("/", "~/"))]
        non_files = [a for a in args if a not in files]
        if not files:
            return fail("name the file to read")
        for f in files:
            real = os.path.realpath(f.replace("~", _home(), 1))
            allowed = (f in READABLE_FILES or real in READABLE_FILES or PROC_FILE.match(f) or any(f.startswith(p) for p in READABLE_PREFIXES[:-1])
                       or re.fullmatch(re.escape(_home()) + r"/\.config/(autostart|systemd/user)/[\w@.-]+", f.replace("~", _home(), 1))
                       or re.fullmatch(re.escape(_home()) + r"/\.(bashrc|profile|zshrc|bash_profile)", f.replace("~", _home(), 1)))
            if not allowed:
                return fail("only a short list of system and startup files can be read this way")
            if SENSITIVE_PATH.search(f) or SENSITIVE_PATH.search(real):
                return fail("that file can hold secrets")
        if prog in ("head", "tail"):
            return ok() if all(re.fullmatch(r"-n|\d{1,5}|-\d{1,5}", a) for a in non_files) else fail("only -n N")
        if prog == "grep":
            pats = [a for a in non_files if not a.startswith("-")]
            fl = [a for a in non_files if a.startswith("-")]
            return ok() if len(pats) == 1 and set(fl) <= {"-E", "-i", "-n", "-c", "-F", "-w", "-v", "-a", "-m"} and len(pats[0]) < 120 else fail("grep with one pattern and simple flags")
        return ok() if not non_files else fail("cat takes only file names")
    return fail("not on the list of read-only checks LinuxGuardian will run for you")


def run_checked(cmd: str, level: str = "standard") -> dict:
    """Run an allow-listed command (never through a shell, never elevated). Returns {'ok', 'output', 'reason'}."""
    v = check_command(cmd)
    if not v.runnable:
        return {"ok": False, "output": "", "reason": v.reason}
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": _home()}
    try:
        p = subprocess.run(v.argv, capture_output=True, text=True, timeout=RUN_TIMEOUT, stdin=subprocess.DEVNULL, env=env, check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "", "reason": f"timed out after {RUN_TIMEOUT}s"}
    except OSError as exc:
        return {"ok": False, "output": "", "reason": f"couldn't run: {exc.strerror or exc}"}
    out = (p.stdout + (("\n" + p.stderr) if p.stderr.strip() else ""))[:OUTPUT_LIMIT]
    return {"ok": True, "output": redact(out, level).text, "reason": "", "exit": p.returncode}
