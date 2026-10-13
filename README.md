# ssh-honeypot

Honeypot SSH en Python (Paramiko) avec rapport statistique. Mini-projet de cybersécurité défensive réalisé par Ammar Kaam, étudiant en Administration et Sécurité des Systèmes d'Information.

> **Toutes les données de ce projet viennent d'un laboratoire isolé** : attaque simulée avec Hydra contre mon propre honeypot, dans un réseau privé. Ce ne sont pas des attaques réelles venues d'Internet.

## Ce que fait le projet

- Un faux serveur SSH qui imite OpenSSH (bannière) et écoute sur un port non standard (2222 par défaut).
- Il **refuse toujours** toute authentification : personne n'obtient jamais d'accès ni de terminal.
- Il enregistre chaque tentative (date, IP, utilisateur, mot de passe) dans un fichier JSON Lines.
- `report.py` lit le journal et produit des statistiques, un tableau de bord PNG et un rapport HTML (adresses IP masquées).

Fonctionnement : attaquant, puis faux serveur SSH, puis fichier journal, puis `report.py`, puis graphiques et rapport.

## Sécurité

- Écoute sur `127.0.0.1` par défaut. Le programme **refuse de démarrer** sur `0.0.0.0` (toutes les interfaces) : il faut donner une adresse précise.
- Maximum 10 connexions simultanées et 30 secondes par session.
- Texte reçu tronqué à 100 caractères, affiché sans caractères dangereux et échappé dans le rapport HTML.
- Adresses IP masquées dans les rapports (`192.168.x.x`).
- La clé du serveur (`host_key`) et le journal brut (`*.jsonl`) sont exclus de Git et ne doivent jamais être publiés.

## Installation

    git clone https://github.com/kaamAmmar/ssh-honeypot.git
    cd ssh-honeypot
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## Utilisation

    python3 honeypot.py                        # écoute sur 127.0.0.1:2222
    python3 honeypot.py --host 192.168.75.10   # adresse précise d'un réseau privé de labo
    python3 report.py                          # génère report/dashboard.png et report/report.html
    pytest -v                                  # lance les 14 tests

Pour tester, un client SSH classique suffit : `ssh -p 2222 test@127.0.0.1`. Tous les mots de passe seront refusés et chaque essai sera noté dans `attempts.jsonl`.

## Test de laboratoire

- Deux machines virtuelles (Ubuntu pour le honeypot, Kali pour l'attaque) reliées par un réseau privé de type Host-only, sans accès à Internet ni à mon réseau personnel.
- Première passe Hydra : 6 utilisateurs et 40 mots de passe, soit 240 essais prévus. Le honeypot en a enregistré 243, car Hydra a réessayé 3 combinaisons.
- Total enregistré dans le journal de test : 299 tentatives.
- Le honeypot a tenu sans planter. Les classements du rapport reflètent **ma liste de test**, pas le comportement d'attaquants réels.

## Tests

14 tests automatiques (pytest) vérifient notamment que toute authentification est refusée, que le texte est tronqué, que le journal contient une ligne par tentative, que les IP sont masquées et que le HTML échappe les textes piégés.

## Limites

- Pas de faux terminal : le honeypot n'enregistre aucune commande.
- Les tentatives par clé publique ne sont pas détectées.
- IPv4 uniquement.
- Pas d'alertes et pas de géolocalisation des adresses IP.
- Les résultats viennent d'un laboratoire : ils ne représentent pas la réalité d'un serveur exposé sur Internet.
- Non prévu pour être exposé sur Internet depuis un réseau personnel.

## Légalité et éthique

Le projet a été testé uniquement sur mes propres machines, dans un laboratoire isolé. Ne l'exposez pas sur un réseau que vous ne maîtrisez pas, ne le lancez jamais sur le port 22 d'un vrai serveur et ne publiez jamais le journal brut ni la clé du serveur.

## Pistes d'amélioration

- Alerte Telegram lors d'une rafale de tentatives.
- Géolocalisation des IP et carte des pays d'origine.
- Bannissement automatique des IP récidivistes.
- Faux terminal pour observer les commandes.
- Envoi des journaux vers un SIEM comme Wazuh.
