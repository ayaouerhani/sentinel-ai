import glob
import os

import numpy as np
import pandas as pd

FILES = sorted(glob.glob("data/cic/MachineLearningCVE/*.csv"))
print(f"{len(FILES)} fichiers trouvés\n")

frames = []
for path in FILES:
    # encoding latin-1: el fichier mta3 WebAttacks fih caractère spécial
    df = pd.read_csv(path, low_memory=False, encoding="latin-1")
    df.columns = df.columns.str.strip()  # el colonnes 3andhom espaces fil awel
    df["source_file"] = os.path.basename(path).split(".pcap")[0]
    frames.append(df)
    print(f"{len(df):>9} lignes | {df['source_file'].iloc[0]}")

data = pd.concat(frames, ignore_index=True)
data["Label"] = data["Label"].str.replace(r"[^\x00-\x7F]", "-", regex=True)

print("\nTotal:", data.shape)

print("\n=== Labels ===")
print(data["Label"].value_counts().to_string())

# Nettoyage: inf et NaN
num = data.select_dtypes(include=[np.number]).columns
data[num] = data[num].replace([np.inf, -np.inf], np.nan)
n_bad = data[num].isna().any(axis=1).sum()
print(f"\nLignes avec inf/NaN: {n_bad} ({n_bad / len(data):.2%})")
data = data.dropna(subset=num).reset_index(drop=True)
data["is_attack"] = (data["Label"] != "BENIGN").astype(int)
print(f"Après nettoyage: {len(data)} lignes | attaques: {data['is_attack'].mean():.1%}")

# Features elli sniff.py ynajem yesta5rejhom: kif ykoun esmhom fil CIC?
wanted = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "SYN Flag Count", "FIN Flag Count",
    "RST Flag Count",
]
print("\n=== Features mta3 sniff.py fil CIC ===")
for c in wanted:
    print(("OK       " if c in data.columns else "MANQUANT ") + c)
print("Colonne Protocol:", "Protocol" in data.columns)

data.to_parquet("data/cic/cic_all.parquet", index=False)
print("\nSauvegardé: data/cic/cic_all.parquet")