#!/usr/bin/env sh
# NetGuard launcher for macOS / Linux:  ./netguard.sh   (no install needed)
cd "$(dirname "$0")" || exit 1
PY=$(command -v python3 || command -v python) || { echo "Python 3.11+ is required."; exit 1; }

while true; do
  cat <<'MENU'

  NetGuard - network intrusion detection
  ======================================
  1  Demo dashboard (fictional network)
  2  Monitor my network (dashboard + scanning)
  3  Stop NetGuard
  4  Validate detections (replay attack simulations)
  5  Analyze the sample attack capture (.pcap)
  6  Quit
MENU
  printf "  Choose 1-6: "; read -r choice
  case "$choice" in
    1) "$PY" -m netguard demo ;;
    2) "$PY" -m netguard serve --open ;;
    3) "$PY" -m netguard stop
       for p in 8001 8002 8003; do "$PY" -m netguard stop --port "$p" 2>/dev/null; done ;;
    4) "$PY" -m netguard validate ;;
    5) "$PY" -m netguard pcap samples/mitm_kill_chain.pcap ;;
    6|q) exit 0 ;;
  esac
done