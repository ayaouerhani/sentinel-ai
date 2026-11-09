import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

if len(sys.argv) < 2:
    print("Usage: python src\\monitor.py <IP_interface> [fenetre_secondes]")
    sys.exit(1)

iface_ip = sys.argv[1]
window = int(sys.argv[2]) if len(sys.argv) > 2 else 20

print(f"Monitoring de {iface_ip} (fenêtres de {window}s). Ctrl+C pour arrêter.", flush=True)

n = 0
try:
    while True:
        n += 1
        cap = subprocess.run(
            [PY, str(ROOT / "src" / "capture" / "sniff.py"), str(window), iface_ip],
            cwd=ROOT, capture_output=True, text=True,
        )
        stamp = time.strftime("%H:%M:%S")

        if "introuvable" in cap.stdout:
            print(f"[{stamp}] Interface {iface_ip} introuvable. Arrêt.", flush=True)
            sys.exit(1)
        if cap.returncode != 0:
            print(f"[{stamp}] fenêtre {n}:  0 flows (réseau silencieux)", flush=True)
            continue

        det = subprocess.run(
            [PY, str(ROOT / "src" / "model" / "detect_live.py")],
            cwd=ROOT, capture_output=True, text=True,
        )
        if det.returncode != 0:
            print(f"[{stamp}] fenêtre {n}: erreur détection: {det.stderr[-300:]}", flush=True)
            continue

        lines = det.stdout.strip().splitlines()
        print(f"[{stamp}] fenêtre {n}: {lines[0] if lines else ''}", flush=True)
        for line in lines[1:]:
            print("    ", line, flush=True)
except KeyboardInterrupt:
    print("\nMonitoring arrêté.", flush=True)