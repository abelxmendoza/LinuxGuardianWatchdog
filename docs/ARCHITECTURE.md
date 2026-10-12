# Architecture

## Design principle

Keep the GUI thin. All real security work happens in standalone shell/python
scripts under `LinuxGuardianSuite/` that:

- can be run standalone from a terminal with no GUI at all
- print human-readable progress plus a machine-readable summary line
- never delete anything outright — destructive actions go through a
  quarantine directory (`~/.linuxguardian/quarantine/`) with a dry-run mode
  on by default

The GUI (`LinuxGuardianSuiteUI/`) is a process-execution shell around these
scripts: it shows buttons/pages, runs the script as a subprocess, and streams
stdout into the UI. This mirrors the macOS original's split between
SwiftUI-as-orchestrator and bash-as-worker.

## Local data

All state lives under `~/.linuxguardian/`:

```
~/.linuxguardian/
├── config                # user config, sourced by config.sh
├── baselines/            # SHA-256 integrity baselines per monitored dir
├── checkpoints/          # resumable scan progress
├── quarantine/           # remediation staging area (never auto-deleted)
├── logs/
└── incidents/            # structured incident records for the UI
```

## Script contract

Every script under `LinuxGuardianSuite/` sources `config.sh` and `utils.sh`
first, supports `-h/--help`, and exits non-zero on failure. Scripts that can
alter the system support `--dry-run` (default) and require an explicit
`--apply` to make changes.

## Privilege model (Updates)

Installing software needs root, and the machine has no passwordless sudo. The
Updates feature therefore never handles a password: `linux_updates.sh --apply`
asks the desktop's own polkit prompt (`pkexec`), and only fixed, hard-coded
package-manager scripts run as root (`tests/test_updates.sh` asserts these
contain no variable or command interpolation, so what runs as root is exactly
what is written in the file).

Deliberate limits:

- `apt-get upgrade`, never `full-upgrade`/`dist-upgrade`/`autoremove`: it can't
  remove packages. Anything that would need that (a GPU driver version change
  is the usual case) is shown as "held back" for the user to review.
- No Stop button during an install. The root side can't be safely interrupted
  (killing dpkg mid-unpack leaves half-configured packages), and the script
  keeps draining the installer's output to a log even if the window is closed,
  so closing the GUI can't SIGPIPE apt/dpkg half-way through.
- Security-only mode reuses `unattended-upgrade`, the same tool that applies
  Ubuntu's daily security patches.
- Release guard: before any install (dry runs included) `update_inventory.py --guard`
  checks every apt source file (one-line and deb822) and every pending package's
  Ubuntu origin against the running release, and fails closed if the release can't
  be determined. It blocks with exit code 3; there is deliberately no override flag.
- Holds (`--hold`/`--unhold`) are the one root action that takes *data* (package
  names). They arrive as positional arguments (`"$@"`), never spliced into the script
  text, are filtered to valid Debian package names in Python and bash, and are
  validated a third time as root. Group patterns are exact on purpose (a `libcu`
  prefix would also hold libcurl4/libcups2 and block *their* security fixes).
  Holds use plain `apt-mark hold`, so apt itself is the source of truth and there's
  no private state to drift.

## Privilege model (scanner: definitions + rootkit check)

Two more fixed root scripts, run the same way (`lg_run_privileged` in `utils.sh` is the
one shared helper; `linux_updates.sh` uses it too):

- `PRIV_SCRIPT_FRESHCLAM`: `freshclam`, nothing else. Exit 126/127 from pkexec means the
  prompt was dismissed: reported as "cancelled", exit code 2, nothing changed.
- `PRIV_SCRIPT_RKHUNTER`: `rkhunter --check --sk --nocolors --no-mail-on-warning`. Opt-in per scan
  (`--rootkit`; a checkbox in the app). Without it, no password prompt ever appears and the
  scan is saved as `rootkit_check: needs_root`.

What is deliberately **not** automated:

- `rkhunter --propupd` is never run by a scan. It tells rkhunter "the system as it is now is the good
  baseline", so run blindly it would bless a compromised system. Ubuntu's `APT_AUTOGEN=false` means the
  baseline goes stale after package updates, so a real run shows many "file properties have changed"
  warnings. They are counted separately and explained. The only path to a refresh is the previewed one
  (`--refresh-rootkit-baseline`, or Review rootkit baseline in the app): `rkhunter_baseline.py` checks every
  warned file against the package that owns it (`dpkg -S` + `dpkg --verify`) and the refresh is offered ONLY
  if every single warning is explained that way. A file no package owns, one that differs from its package,
  a non-file warning, or a count that doesn't add up blocks it, and then no password prompt appears at all.
  The console format of rkhunter was inferred (its detailed log is root-only); the analysis fails closed.
- `rkhunter --update`: dead on Ubuntu (`WEB_CMD=/bin/false`, `UPDATE_MIRRORS=0`).
- Enabling `clamav-freshclam` happens only when the user clicks "Turn on automatic updates" and confirms: `PRIV_SCRIPT_ENABLE_FRESHCLAM` is `systemctl enable --now` for that one unit and nothing else.

Honest bookkeeping: every saved scan records `rootkit_check` as `ran | needs_root | cancelled | not_run`.
"Clean" is only ever shown when it was `ran`. No Stop during the root step (the user can't signal a
root process); the app says so instead of showing a button that doesn't work.

`scanner_health.py` is read-only: definitions age (from `daily.c[lv]d`, not the months-old `main.cvd`),
updater service state, rkhunter baseline age and the last check status. Shown on the Dashboard.

## Security score

`linux_security_audit.sh` is the single place the score is computed: a pass is worth 1, a warning
1/2, a failure 0, and it prints `Rating: N%`. The app only reads that line (`score.py`), so the
CLI and the window can't disagree. Two checks measure whether a scan result can be trusted at all:
virus definitions no older than 2 days, and a rootkit check that has actually run.

## Moving apps between laptops

`app_manifest.py` writes a plain list (apt manual installs with their origin, snaps, flatpaks, the third-party
repositories they came from with credentials stripped, holds). It contains nothing from `$HOME`.
`--plan` recomputes everything on the target; the file is never trusted: names are matched against strict
patterns at three independent layers (planner, `linux_apps.sh`, the root script itself) and each layer is
tested to hold on its own. Import refuses on a different release or CPU, skips hardware-specific packages
(kernel, NVIDIA/CUDA/Jetson, firmware) by name rule even if the file claims otherwise, never adds a repository
or key (third-party apps are listed with the repo they need), never removes (`apt-get install --no-remove`),
and installs classic (unconfined) snaps only when explicitly included.

## Blue team: sensors, incidents, evidence

`sensors.py` runs every 5 minutes (a user systemd timer, no root) and watches for what an attack DOES: failed logins and a
login right after them, new accounts and admin-group changes, sensitive sudo use, programs running from /tmp or whose file
was deleted, programs pretending to be kernel threads, a program talking to the internet for the first time or on a port
known for malware, new startup entries/cron jobs/services, new USB devices (keyboard+storage composites), and new
executables dropped in /tmp or `~/.local/bin`. Plain, inspectable rules, no AI. Design points that matter:

- **Learn first.** The first run only records what is normal; network behaviour stays quiet for 3 days. Everything is
  deduplicated (a finding isn't repeated for 24 h), so a five-minute timer doesn't flood you.
- **Tunable.** "This is expected" adds a path to `~/.linuxguardian/sensors_allow.json` (broad paths like `/tmp/` are refused).
  AppImage mounts and package-upgrade "deleted" binaries under /usr are already treated as normal.
- **Honest about itself.** Real finding from the first run on this laptop: our own `sudo -n` audit probe wrote
  "a password is required" lines that looked like failed sudo; those are filtered.
- **Secrets never stored.** Command lines are scrubbed of tokens/passwords/bearer values/URL credentials before anything is written.

`incidents.py` correlates events that share an entity (same program, user, address or file) within two hours into ONE story,
names it ("A program running from a temporary folder is talking to the internet"), and always says why it matters, why it
may be harmless, and what to check. Interpreters (python, node, bash) never glue unrelated events together; lone routine
notes and integrity changes alone never become incidents. `evidence.py` collects a read-only bundle (process tree,
connections, logins, startup entries, program paths/owners/hashes) into a mode-700 folder, never reading process
environments or your documents. Detection stays separate from remediation: nothing here stops, blocks or deletes.

## AI investigator

Opt-in, advisory, and unable to act. `ai_investigator.py` turns an incident plus its evidence into a redacted dossier, shows you
exactly what would be sent, asks a model (local Ollama, or Claude through Anthropic's official SDK), and validates the reply
before you see it. It is deliberately not part of detection: sensors detect, the AI explains.

The threat model is that evidence is attacker-influenced text (process names, command lines, log lines, usernames), so a
hostile string can try to talk to the AI. Defences, in layers, each tested:

1. **Redaction first** (`ai_safety.redact`): secrets and private keys, your username, hostname, home path, emails and MAC
   addresses are removed before the preview and before sending; "strict" also generalises public IPs and flattens paths.
2. **Nothing leaves without your click.** The preview shows the exact JSON. Cloud requests need explicit confirmation every
   time (`NeedsConfirmation`); the CLI exits with code 4 until `--confirm-cloud`.
3. **Evidence is data, not instructions.** It travels as one JSON value behind a random nonce the attacker can't guess, and the
   system prompt says to treat instructions found in evidence as a sign of attack (`injection_suspected`).
4. **The model's reply is untrusted too.** Strict schema (structured outputs for Claude, `format` for Ollama), then
   `validate_result`: unknown fields dropped, enums and lengths enforced, every suggested command classified.
5. **No path to act.** The module imports no subprocess, kill, acknowledge or allow-list code (a static test asserts it). Only a
   short allow-list of read-only commands (`ai_safety.check_command`) can get a Run button, only on your click, with no shell,
   no sudo, a minimal environment, a timeout, and redacted, capped output. Secrets paths (`environ`, `.ssh`, `.aws`, ...) are denied.
6. **The AI never overrules the sensors.** If it calls something harmless while the sensors rate it warning/critical, the UI says
   they disagree and the sensors' rating stands. It can't mark anything reviewed.
7. **Auditable.** Every request and reply is saved mode 600 in `~/.linuxguardian/ai_log/`, including the exact text sent.

An adversarial test feeds five classic injections and a "model" that obeys every one of them; nothing hostile becomes runnable,
nothing is silenced or allow-listed, and nothing executes after the model answers. Claude calls follow the official SDK: default
model `claude-opus-5-5`, JSON-schema structured output, no tools, no sampling parameters, and the server-side `fallbacks` beta
requested by default with automatic degradation to a plain request if the beta isn't accepted.

## Activity view

Scripts print terminal text; the Dashboard shows it as plain-language CARDS instead. `activity.py` (pure Python, no GTK)
reads the lines as they stream and keeps a structured picture: a verdict sentence, one card per step (Malware scan,
Rootkit check, Security audit, File integrity, Virus definitions), and GROUPS inside a card with an explanation, for example
"System programs that differ from rkhunter's saved copy (81)": why that is expected after updates and how to confirm it.
rkhunter's unusual warnings (shared memory, /dev, hidden files, account-file changes) each get a sentence, and anything
that looks like a real compromise sign is never softened. It is tested against REAL output from this machine
(`tests/fixtures/*.txt`), including a scan with 86 rkhunter warnings. The raw lines are still available under
"Technical details". Lessons from that real run are fixed at the source: the scan used to report "0 warnings" because it
counted a log format rkhunter doesn't print on the console, and the baseline check treated core tools as unowned because
Ubuntu's `/bin` -> `/usr/bin` merge hides them from `dpkg -S` (symlinks such as `/usr/bin/mail` are now judged by their target).

## Hardening, VPN status and diagnostics

`hardening.py` is a checklist. Each check reads the machine without root and returns a state
(ok / attention / info / unknown), a plain-language summary, WHY it matters, and optional fixes. Every fix shows
what it will change before it runs, records what it replaced in `~/.linuxguardian/state/hardening_undo.json`, and can
be undone. Fixes that change only your own settings (screen lock, Screen Sharing, file permissions, the daily timer)
run as you; the three that need root (kernel settings, ufw IPv6, ufw logging) go through `linux_hardening.sh` with
fixed scripts, allow-listed words and one password prompt. Details worth knowing:

- A failed multi-step fix rolls back; a "limit Screen Sharing to Tailscale" fix verifies the listener really narrowed and
  reverts itself if it didn't.
- Kernel settings deliberately skip `rp_filter` (strict mode breaks routing when Tailscale/Proton are up) and
  `ptrace_scope` (breaks attaching debuggers to your own ROS processes).
- "Fix the recommended ones" only includes problems with exactly one recommended remedy; choices that depend on how you
  use the laptop (should Screen Sharing be off, or just locked down?) are left to you.
- Secret values are never read into the UI: the Screen Sharing check reports that a password is stored in a reversible
  form but never displays it.

`vpn_status.py` reads tailscale, NetworkManager, `ip` and `resolvectl` and judges the combination: which interface owns the
default route, whether Tailscale traffic still reaches Tailscale while Proton is up, DNS and IPv6 leaks, a Tailscale
exit node stacked on another VPN, address-range (CGNAT) overlap, and a Proton kill switch left armed. It sends nothing
anywhere unless you press "Check my public IP" (one request to Cloudflare's trace page). The Proton heuristics come from
Proton's own support pages and user reports, not from a published interface contract, so treat them as best-effort.

`diagnostics.py` reports by FEATURE (Rootkit check: unavailable, needs rkhunter) rather than by tool, checks that a polkit
agent is running so password prompts can appear, that the data directory is writable, and that every script in the install
still parses.

## Robot networking (ROS 2 firewall helper)

A default-deny ufw blocks DDS discovery between laptop and robot, and the usual fixes (open a huge range,
turn the firewall off) are worse than the problem. `ros_firewall.py` computes the narrowest rules instead:
one peer address (never "any", never wider than /16), the UDP range of the detected `ROS_DOMAIN_ID`
(`7400 + 250*domain`, 250 ports), and only the presets ticked. `ROS_LOCALHOST_ONLY=1` is recognised: no rules
needed. `linux_ros_firewall.sh --apply` refuses unless ufw is the active firewall, adds or removes exactly the
previewed rules in ONE privileged call, validates every group before touching any (one bad rule stops all of
them), builds the rule comment from an allow-list, and never changes the default policy or enables/disables ufw.
Allow-rules are root-only to read, so the app can't list what already exists; ufw skips duplicates.

## Timeline and notifications

`timeline.py` folds identical findings (a count changing doesn't make a finding new) and lets you mark
one as seen; nothing is deleted. The audit only records a finding when it is NEW and records a "Resolved"
event when it goes away (`audit_events.py`). `notify_events.py` announces events newer than its last run,
grouped into one notification, and never replays history on first use.

## File integrity

`integrity.py` (called by `linux_watchdog.sh`) watches ~/Documents and the places malware restarts from:
shell start-up files, ~/.ssh, autostart entries, user systemd units, `/etc/ld.so.preload`, `/etc/passwd`.
Changes are classified modified / new / missing; a new file in a persistence location is a warning, a new
document is information. `.git` internals, caches and the honeypot are skipped. The honeypot is only ever
`stat`ed (hashing it, or scanning it with ClamAV, reads it and used to set off its own alarm), and an access
is reported once. Events are capped per check so a mass change is one summary, not hundreds of files.

## Branding

The palette in `style.css` is sampled from the wolf logo: near-black violet ground, neon-violet
outline (`omega_violet`), amber eyes (`omega_yellow`), ember-orange "WATCHDOG" (`omega_orange`).
`images/LinuxGuardianLogo.png` is the original; the head-only rounded icon is installed into the
user's icon theme by `install_desktop_entry.sh` (`Icon=linuxguardian-watchdog`, matched to the window
by `StartupWMClass`).

## Security events

`events.py` is the one definition of what a security event looks like. Detectors
write small JSON files into `~/.linuxguardian/incidents/`; the required core is
the same four fields the shell helper `lg_record_incident` has always written
(`timestamp`, `category`, `severity`, `message`), plus optional structured fields
(`event`, `status`, `process`, `pid`, `port`, `protocol`, ...) so a future timeline,
notification or anomaly detector doesn't have to parse sentences. Severities stay
`info | warning | critical`: one vocabulary, not two. Old records stay readable.

Detectors that run repeatedly (`linux_exposure.sh --record`) only write an event when
something is **new or changed**, using a small state file, so a daily timer doesn't
bury the timeline in repeats.

## Exposure detection (detection only)

`exposure_inventory.py` reads `ss`, `ip` and the firewall's *readable* state, and never
closes a port, stops a service or changes a rule. It needs no root, and says so where
that limits it:

- Listeners owned by root or another user are reported as "owner not visible", not guessed.
- Firewall allow-rules are root-only. What is readable is whether ufw is enabled and its
  default inbound policy, so coverage is reported as "default-deny, allow-rules can't be
  checked", and a default-deny firewall lowers a finding by one level but never erases it.
- Severity is a small pure function (class of service x scope x firewall) that the tests
  table-check; loopback-only listeners are never findings.

## GUI stack

- **GTK4** — native Linux widget toolkit (the closest equivalent to AppKit/
  SwiftUI on macOS; ships with GNOME and is well supported on KDE/other DEs
  via GTK theming)
- **libadwaita** — GNOME's modern application design layer on top of GTK4
  (adaptive layouts, view switchers, toast notifications) — gives the app a
  native, modern look rather than a generic cross-platform one
- **PyGObject** — Python bindings for GTK4/libadwaita, chosen over C for
  faster iteration while prototyping; a future native rewrite (C or Vala)
  is possible once the feature set stabilizes

## Theme: "Omega Black-Ops"

Ported from the macOS original's terminal theme (`theme_omega_black_ops.sh`):
near-black background (`#0d0d0d`), light-gray text (`#e5e5e5`), purple accent
(`#8c00ff`) for primary/suggested actions, red (`#ff1100`) for destructive
actions and critical status, yellow (`#ffe600`) for warnings. Defined in
`LinuxGuardianSuiteUI/resources/style.css` as GTK4 CSS (`@define-color` +
selectors targeting libadwaita's built-in style classes like
`.suggested-action`/`.destructive-action`), loaded and forced to dark mode in
`main.py` regardless of the system's light/dark setting — the original is a
deliberately dark security-suite look, not a system-theme follower.

## Compatibility notes

This targets libadwaita **1.1+** (Ubuntu 22.04's version), not just the
latest. That ruled out a couple of newer widgets during development:
`Adw.ToolbarView` and `Adw.MessageDialog` need 1.4/1.2 respectively and
aren't used here — `window.py` builds the header/content layout by hand
with a plain `Gtk.Box`, and `dialogs.py` has a small hand-rolled confirm
dialog instead. If you're developing against a newer libadwaita and want to
adopt those, gate it behind a version check rather than replacing them
outright, so older systems don't break.
