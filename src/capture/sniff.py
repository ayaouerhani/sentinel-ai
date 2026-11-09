import sys

import pandas as pd
from scapy.all import ICMP, IP, TCP, UDP, conf, sniff

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 30   # thawéni
IFACE_ARG = sys.argv[2] if len(sys.argv) > 2 else None     # IP wala esm el carte

IFACE = None
if IFACE_ARG:
    IFACE = next(
        (i for i in conf.ifaces.values() if IFACE_ARG in (i.ip, i.name)), None
    )
    if IFACE is None:
        print(f"Interface '{IFACE_ARG}' introuvable.")
        sys.exit(1)

flows = {}


def handle(pkt):
    if IP not in pkt:
        return
    ip = pkt[IP]
    if TCP in pkt:
        proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        plen = max(0, ip.len - ip.ihl * 4 - pkt[TCP].dataofs * 4)
    elif UDP in pkt:
        proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        plen = max(0, pkt[UDP].len - 8)
    elif ICMP in pkt:
        proto, sport, dport = "ICMP", 0, 0
        plen = max(0, ip.len - ip.ihl * 4 - 8)
    else:
        return

    # Flow bidirectionnel: nafs el connexion fi el 2 sens = nafs el key
    a, b = (ip.src, sport), (ip.dst, dport)
    key = (proto,) + (a + b if a <= b else b + a)

    t = float(pkt.time)
    f = flows.get(key)
    if f is None:
        f = flows[key] = {
            "proto": proto, "src": ip.src, "sport": sport,
            "dst": ip.dst, "dport": dport, "start": t, "end": t,
            "fwd_pkts": 0, "bwd_pkts": 0, "fwd_bytes": 0, "bwd_bytes": 0,
            "syn": 0, "fin": 0, "rst": 0,
        }
    f["end"] = t

    if ip.src == f["src"] and sport == f["sport"]:
        f["fwd_pkts"] += 1
        f["fwd_bytes"] += plen
    else:
        f["bwd_pkts"] += 1
        f["bwd_bytes"] += plen

    if TCP in pkt:
        flags = int(pkt[TCP].flags)
        f["syn"] += bool(flags & 0x02)
        f["fin"] += bool(flags & 0x01)
        f["rst"] += bool(flags & 0x04)

print(f"Capture pendant {DURATION}s... (ouvre un site web, fais un ping, etc.)")
sniff(iface=IFACE, prn=handle, store=False, timeout=DURATION)

df = pd.DataFrame(flows.values())
if df.empty:
    print("Aucun paquet capturé. Vérifie l'interface (argument 2) et Npcap.")
    sys.exit(1)

df["duration"] = (df["end"] - df["start"]).round(3)
df["total_pkts"] = df["fwd_pkts"] + df["bwd_pkts"]
df["total_bytes"] = df["fwd_bytes"] + df["bwd_bytes"]
df = df.drop(columns=["start", "end"]).sort_values("total_bytes", ascending=False)

print(f"\nFlows: {len(df)} | Paquets: {df['total_pkts'].sum()}")
print(df.head(15).to_string(index=False))

df.to_csv("data/flows_live.csv", index=False)
print("\nSauvegardé: data/flows_live.csv")