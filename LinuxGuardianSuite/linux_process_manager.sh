#!/usr/bin/env bash
# linux_process_manager.sh — the "process killer": list and terminate processes.
#
# --list is implemented in process_inventory.py (JSON lines with group,
# impact, cmdline, origin, systemd unit, listening ports). --kill stays here.
#
# Usage:
#   linux_process_manager.sh --list [--sort cpu|mem]
#   linux_process_manager.sh --kill PID [--force]
#   linux_process_manager.sh --kill-name NAME [--force]
#   linux_process_manager.sh -h | --help
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck source=config.sh
source "$SCRIPT_DIR/config.sh"
# shellcheck source=utils.sh
source "$SCRIPT_DIR/utils.sh"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//;1d'; }

MODE="" TARGET="" SORT="cpu" FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --list) MODE="list" ;;
    --sort) SORT="${2:-cpu}"; shift ;;
    --kill) MODE="kill"; TARGET="${2:-}"; shift ;;
    --kill-name) MODE="kill-name"; TARGET="${2:-}"; shift ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) lg_error "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

# Well-known infrastructure processes: ending these can log you out or take
# down the whole system, regardless of which user owns them. Never surface
# these as "safe".
CRITICAL_NAMES=" systemd init kthreadd Xorg Xwayland gnome-shell gdm gdm3
lightdm sddm NetworkManager systemd-logind systemd-journald systemd-udevd
dbus-daemon polkitd pulseaudio pipewire wireplumber udisksd upowerd
wpa_supplicant sshd containerd dockerd "

is_critical_name() {
  case "$CRITICAL_NAMES" in *" $1 "*) return 0 ;; esac
  return 1
}

# GNOME session helpers often inherit DISPLAY so they look like "apps".
# They are desktop infrastructure — not something the user opened.
is_desktop_infra() {
  case "$1" in
    gsd-*|gvfsd|gvfsd-*|gvfs-*|ibus-*|evolution-*|xdg-desktop-portal*|xdg-document-portal|xdg-permission-store|dconf-service|goa-daemon|at-spi*|vino-server)
      return 0
      ;;
  esac
  return 1
}

_proc_cmdline() {
  tr '\0' ' ' 2>/dev/null < "/proc/$1/cmdline" | tr '|\n' '  '
}

_proc_exe() {
  readlink "/proc/$1/exe" 2>/dev/null | tr '|\n' '  ' || true
}

is_ros_cmd() {
  printf '%s\n' "$1" | grep -qiE '/opt/ros/|ros2|rclpy|rclcpp|topic_tools|ament_'
}

classify() {
  # Sets globals PROC_KIND and PROC_RISK for pid/user/comm.
  # NOTE: 2>/dev/null must come BEFORE the input redirect on these reads —
  # if the input file has already vanished (process exited) or is
  # unreadable (another user's /proc/<pid>/environ), bash's own "No such
  # file"/"Permission denied" is emitted while *opening* that redirect, so
  # a trailing "2>/dev/null" is too late to catch it.
  local pid="$1" user="$2" comm="$3"
  PROC_KIND="system"
  # /proc/<pid>/cmdline always stat()s as size 0 (it's a synthetic file) —
  # "-s" can't detect emptiness; actually read it instead. Kernel threads
  # have a genuinely empty cmdline.
  if [ -z "$(tr -d '\0' 2>/dev/null < "/proc/$pid/cmdline")" ]; then
    PROC_KIND="kernel"
  elif is_critical_name "$comm" || is_desktop_infra "$comm"; then
    # Desktop/system infrastructure (gnome-shell, Xorg, gsd-*, gvfs...)
    # often runs under your user with DISPLAY set, but it isn't "your app".
    PROC_KIND="system"
  elif [ "$user" = "${USER:-$(id -un)}" ]; then
    if tr '\0' '\n' 2>/dev/null < "/proc/$pid/environ" \
         | grep -q '^\(DISPLAY\|WAYLAND_DISPLAY\)='; then
      PROC_KIND="app"
    else
      PROC_KIND="background"
    fi
  fi

  # ROS 2 nodes inherit DISPLAY from a terminal but are not desktop apps.
  case "$comm" in
    rviz*|gazebo*|gz*) ;;
    *)
      if is_ros_cmd "$(_proc_cmdline "$pid")"; then
        PROC_KIND="background"
      fi
      ;;
  esac

  if [ "$PROC_KIND" = "kernel" ] || is_critical_name "$comm"; then
    PROC_RISK="critical"
  elif [ "$comm" = "systemd" ] && [ "$pid" = "1" ]; then
    PROC_RISK="critical"
  elif [ "$comm" = "systemd" ]; then
    PROC_RISK="critical"
  elif [ "$PROC_KIND" = "app" ]; then
    PROC_RISK="safe"
  else
    PROC_RISK="caution"
  fi
}

do_list() {
  local sort_col="-%cpu"
  [ "$SORT" = "mem" ] && sort_col="-%mem"

  local snapshot
  snapshot="$(ps -eo pid,ppid,%cpu,%mem,etimes,user,comm --no-headers --sort="$sort_col")"

  # Precompute child-process counts per parent PID in one pass (avoids
  # spawning a `ps` per row just to count children).
  local -A child_count
  local cnt ppid
  while read -r cnt ppid; do
    [ -n "$ppid" ] && child_count["$ppid"]="$cnt"
  done < <(awk '{print $2}' <<< "$snapshot" | sort -n | uniq -c)

  # Pipe-delimited output: process names (Chrome's "Isolated Web Co", etc.)
  # can legitimately contain spaces, so this can't be space-separated.
  local pid pp cpu mem etimes user comm
  while read -r pid pp cpu mem etimes user comm; do
    [ -z "$pid" ] && continue
    classify "$pid" "$user" "$comm"
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "$pid" "$pp" "$cpu" "$mem" "$etimes" "$user" "$comm" \
      "$PROC_KIND" "$PROC_RISK" "${child_count[$pid]:-0}" \
      "$(_proc_exe "$pid")" "$(_proc_cmdline "$pid")"
  done <<< "$snapshot"
}

do_kill() {
  local pid="$1"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    lg_error "No such process: $pid"
    return 1
  fi
  local sig="TERM"
  [ "$FORCE" -eq 1 ] && sig="KILL"
  if kill "-$sig" "$pid" 2>/dev/null; then
    lg_ok "Sent SIG$sig to PID $pid"
    lg_record_incident "process" "info" "Killed PID $pid with SIG$sig"
  else
    lg_error "Failed to signal PID $pid (owned by another user? try with sudo)"
    return 1
  fi
}

do_kill_name() {
  local name="$1"
  local self_pid=$$
  local pids
  pids="$(pgrep -f "$name" | grep -vx "$self_pid" || true)"
  if [ -z "$pids" ]; then
    lg_warn "No running process matches '$name'"
    return 0
  fi
  local sig="TERM"
  [ "$FORCE" -eq 1 ] && sig="KILL"
  echo "$pids" | while read -r pid; do
    [ -z "$pid" ] && continue
    if kill "-$sig" "$pid" 2>/dev/null; then
      lg_ok "Sent SIG$sig to PID $pid ($name)"
      lg_record_incident "process" "info" "Killed PID $pid ($name) with SIG$sig"
    else
      lg_error "Failed to signal PID $pid ($name)"
    fi
  done
}

case "$MODE" in
  list) python3 "$SCRIPT_DIR/process_inventory.py" --sort "$SORT" ;;
  kill) do_kill "$TARGET" ;;
  kill-name) do_kill_name "$TARGET" ;;
  "") usage; exit 0 ;;
esac
