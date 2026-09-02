#!/usr/bin/env bash
#
# pf-probe.sh -- the connect probe and the pf label-counter readers shared by
# the macOS pf lanes. Sourced, never executed. Every function prints one value
# and exits zero: a measurement has no `|| true`.
#
# One TCP connect, hard 2 s ceiling; prints `open` or `closed:<reason>`. A pf
# `block drop` is SILENT, so a covered-prefix probe times out rather than being
# refused — which is why the caller never reads this on its own.
connect_probe() {
  python3 - "$1" "$2" <<'PY'
import socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2):
        print("open")
except Exception as exc:                                # noqa: BLE001
    print("closed:%s" % type(exc).__name__)
PY
}

# The packets pf counted for one label, summed over every rule carrying it.
# `pfctl -s labels` prints `<label> <evaluations> <packets> <bytes> …`, which is
# what `pfread::parse_labels` reads; both tolerate trailing columns.
label_packets() {
  awk -v want="$1" '$1 == want { sum += $3 } END { print sum + 0 }' "${2:-/dev/null}"
}
# Field 2: how many times the kernel EVALUATED a rule carrying the label. Zero
# after a covered connect means the anchor was never stepped into, which no
# amount of `-s rules` output can reveal.
label_evals() {
  awk -v want="$1" '$1 == want { sum += $2 } END { print sum + 0 }' "${2:-/dev/null}"
}

# A loopback listener started for the duration of one connect, printing `open`
# or `closed:<reason>`. It rules out "the stack cannot connect at all" and no
# more: 127.0.0.1 is in neither protected table and the boot anchor has no
# default deny, so this survives whether or not the anchor is evaluated.
loopback_control_probe() {
  local control_port_file control_pid control_probe
  control_port_file="$1/pf-anchor-control-port"
  rm -f "$control_port_file"
  python3 - "$control_port_file" <<'PY' &
  import socket, sys, time
  srv = socket.socket()
  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  srv.bind(("127.0.0.1", 0))
  srv.listen(4)
  with open(sys.argv[1], "w") as fh:
      fh.write(str(srv.getsockname()[1]))
  srv.settimeout(15)
  deadline = time.time() + 15
  while time.time() < deadline:
      try:
          srv.accept()[0].close()
      except OSError:
          break
PY
  control_pid=$!
  for _ in $(seq 1 30); do [ -s "$control_port_file" ] && break; sleep 0.2; done
  control_probe="closed:NoListener"
  if [ -s "$control_port_file" ]; then
    control_probe="$(connect_probe 127.0.0.1 "$(cat "$control_port_file")")"
  fi
  kill "$control_pid" 2>/dev/null || true
  wait "$control_pid" 2>/dev/null || true
  printf '%s\n' "$control_probe"
  }
