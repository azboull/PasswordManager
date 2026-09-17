# Password Manager CLI

Gestionnaire de mots de passe en ligne de commande, écrit en Python. Les identifiants sont chiffrés localement — rien n'est jamais stocké en clair.

## Fonctionnalités

- Authentification par mot de passe maître (hashé avec `hashlib`, jamais stocké en clair)
- Coffre chiffré (`cryptography` / `Fernet`), avec clé dérivée du mot de passe maître via `PBKDF2HMAC`
- Enregistrement et recherche d'identifiants par site

## Installation

```bash
git clone https://github.com/azboull/PasswordManager.git
cd PasswordManager
python3 -m venv venv
source venv/bin/activate
pip install cryptography
```

## Utilisation

```bash
python main.py
```

Au premier lancement, tu définis ton mot de passe maître. Ensuite :

- `enregistrer` : ajoute un identifiant pour un site
- `chercher` : récupère l'identifiant/mot de passe d'un site
- `help` : liste les commandes
- `quitter` : sauvegarde et ferme

## Sécurité

- Le mot de passe maître n'est jamais stocké : seul son hash SHA-256 est conservé (`master.hash`).
- Les données du coffre (`coffre.enc`) sont chiffrées avec une clé dérivée du mot de passe maître (PBKDF2, 390 000 itérations) et un sel unique (`salt.bin`).
- `master.hash`, `salt.bin` et `coffre.enc` sont exclus du dépôt Git (`.gitignore`) — ils sont propres à chaque installation locale.

## Pistes d'amélioration

- Génération de mots de passe aléatoires sécurisés (`secrets`)
- Migration vers `bcrypt`/`argon2` pour le hash du mot de passe maître
- Tests unitaires (`pytest`)
