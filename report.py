import html
import json
import os
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

LOG_FILE = "attempts.jsonl"


def load_attempts(path=LOG_FILE):
    attempts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                attempts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return attempts


def top(attempts, field, n=10):
    return Counter(a.get(field, "?") for a in attempts).most_common(n)


def per_minute(attempts):
    minutes = Counter(a.get("time", "")[:16] for a in attempts)
    return sorted(minutes.items())


def mask_ip(ip):
    parts = str(ip).split(".")
    if len(parts) == 4:
        return ".".join(parts[:2] + ["x", "x"])
    return "masquee"


def safe_label(text):
    return str(text)[:30].replace("$", "")


def make_dashboard(attempts, out_path="report/dashboard.png"):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fig, ax = plt.subplots(2, 2, figsize=(13, 8))
    fig.suptitle("ssh-honeypot : donnees de laboratoire", fontsize=15)

    pw = top(attempts, "password", 10)[::-1]
    ax[0][0].barh([safe_label(p) for p, _ in pw], [c for _, c in pw])
    ax[0][0].set_title("Mots de passe les plus essayes")

    us = top(attempts, "user", 10)[::-1]
    ax[0][1].barh([safe_label(u) for u, _ in us], [c for _, c in us])
    ax[0][1].set_title("Utilisateurs les plus essayes")

    ips = Counter(mask_ip(a.get("ip", "")) for a in attempts)
    ips = ips.most_common(10)[::-1]
    ax[1][0].barh([i for i, _ in ips], [c for _, c in ips])
    ax[1][0].set_title("Adresses IP (masquees)")

    minutes = per_minute(attempts)
    ax[1][1].bar([m[-5:] for m, _ in minutes], [c for _, c in minutes])
    ax[1][1].set_title("Tentatives par minute (UTC)")
    ax[1][1].tick_params(axis="x", rotation=45)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def make_html(attempts, out_path="report/report.html"):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    def rows(pairs):
        return "".join(
            f"<tr><td>{html.escape(str(v))}</td><td>{c}</td></tr>"
            for v, c in pairs
        )

    ips = Counter(mask_ip(a.get("ip", "")) for a in attempts)
    page = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport ssh-honeypot</title></head><body>
<h1>Rapport ssh-honeypot</h1>
<p><b>Donnees de laboratoire</b> : attaque simulee avec Hydra contre
mon propre honeypot, dans un reseau prive. Ce ne sont pas des attaques
reelles venues d'Internet.</p>
<p>Total : {len(attempts)} tentatives enregistrees.</p>
<img src="dashboard.png" alt="tableau de bord" style="max-width:100%">
<h2>Mots de passe</h2>
<table border="1" cellpadding="4">{rows(top(attempts, 'password', 10))}</table>
<h2>Utilisateurs</h2>
<table border="1" cellpadding="4">{rows(top(attempts, 'user', 10))}</table>
<h2>Adresses IP (masquees)</h2>
<table border="1" cellpadding="4">{rows(ips.most_common(10))}</table>
</body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)


if __name__ == "__main__":
    attempts = load_attempts()
    print(f"Total : {len(attempts)} tentatives")
    for field, label in (("password", "mots de passe"),
                         ("user", "utilisateurs"),
                         ("ip", "adresses IP")):
        print(f"\nTop {label} :")
        for value, count in top(attempts, field, 5):
            print(f"  {count:4d}  {value}")
    print("\nTentatives par minute :")
    for minute, count in per_minute(attempts):
        print(f"  {minute}  {count}")
    make_dashboard(attempts)
    make_html(attempts)
    print("\nrapport genere dans le dossier report/")
