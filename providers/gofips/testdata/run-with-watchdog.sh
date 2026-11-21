#!/usr/bin/env bash
# run-with-watchdog.sh: run a suite with line-buffered output to a log. If it
# is still running after <seconds>, append every thread's stack (gdb) to the
# log, kill it, and exit 124; otherwise exit with the suite's status.
#
# Usage: run-with-watchdog.sh <seconds> <log> <command> [args...]
set -uo pipefail
secs=${1:?usage: run-with-watchdog.sh <seconds> <log> <command> [args...]}
log=${2:?usage: run-with-watchdog.sh <seconds> <log> <command> [args...]}
shift 2
stdbuf -oL -eL "$@" > "$log" 2>&1 &
pid=$!
for _ in $(seq "$secs"); do
  if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; exit $?; fi
  sleep 1
done
echo "watchdog: still running after ${secs}s: $*" | tee -a "$log"
SUDO=(); [ "$(id -u)" = 0 ] || SUDO=(sudo -n)
command -v gdb >/dev/null || { "${SUDO[@]}" apt-get update -qq && "${SUDO[@]}" apt-get install -y -qq gdb; } >/dev/null 2>&1 || true
"${SUDO[@]}" gdb -p "$pid" -batch -ex 'info threads' -ex 'thread apply all bt 30' 2>&1 \
  | grep -vE '^warning|^\[New LWP|^\[Thread debugging' | tee -a "$log"
kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
exit 124
