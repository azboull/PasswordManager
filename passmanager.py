from dataclasses import dataclass, asdict
import hashlib
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

chemin_hash = "master.hash"
chemin_coffre = "coffre.enc"
chemin_sel = "salt.bin"


def charger_hash(chemin):
    with open(chemin, "r") as file:
        return file.read()


def sauvegarder_hash(hash_resultat, chemin):
    with open(chemin, "w") as file:
        file.write(hash_resultat)


def obtenir_sel(chemin=chemin_sel):
    if os.path.exists(chemin):
        with open(chemin, "rb") as file:
            return file.read()
    else:
        sel = os.urandom(16)
        with open(chemin, "wb") as file:
            file.write(sel)
        return sel


def deriver_cle(mot_de_passe, sel):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sel,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(mot_de_passe.encode()))


@dataclass
class Entre:
    Site: str
    Identifiant: str
    Mot_De_Passe: str


class Coffre:
    def __init__(self):
        self.contenu = {}  # site: Entre


def sauvegarder_coffre(coffre, cle, chemin=chemin_coffre):
    data = {site: asdict(entre) for site, entre in coffre.contenu.items()}
    data_bytes = json.dumps(data).encode()

    f = Fernet(cle)
    data_chiffree = f.encrypt(data_bytes)

    with open(chemin, "wb") as file:
        file.write(data_chiffree)


def charger_coffre(cle, chemin=chemin_coffre):
    coffre = Coffre()
    if os.path.exists(chemin):
        with open(chemin, "rb") as file:
            data_chiffree = file.read()
        f = Fernet(cle)
        data_bytes = f.decrypt(data_chiffree)
        data = json.loads(data_bytes)
        for site, infos in data.items():
            coffre.contenu[site] = Entre(**infos)
    return coffre


# --- Authentification ---

if not os.path.exists(chemin_hash):
    mdpa = input("saisir votre mot de passe principal ")
    mdpb = input("confirmez votre mot de passe ")
    while mdpa != mdpb:
        print("veuillez saisir le meme mot de passe")
        mdpa = input("saisir votre mot de passe principal ")
        mdpb = input("confirmez votre mot de passe ")

    hash_resultat = hashlib.sha256(mdpb.encode()).hexdigest()
    sauvegarder_hash(hash_resultat, chemin_hash)
    mot_de_passe_valide = mdpb

else:
    saisie = input("Mot de passe maître : ")
    hash_stocke = charger_hash(chemin_hash)
    if hashlib.sha256(saisie.encode()).hexdigest() != hash_stocke:
        print("Mot de passe incorrect.")
        exit()
    mot_de_passe_valide = saisie

# --- Dérivation de la clé de chiffrement ---

sel = obtenir_sel()
cle = deriver_cle(mot_de_passe_valide, sel)

mdp_stockes = charger_coffre(cle)

# --- Boucle principale ---

while True:
    reponse = input("Que voulez vous faire ? (help pour liste des commandes) : ")

    if reponse == "help":
        print("enregistrer: ajouter un mot de passe \n"
              "chercher: chercher l'identifiant/mot de passe d'un site \n"
              "quitter: quitter")

    if reponse == "enregistrer":
        Site = input("site ? ")
        Identifiant = input("Identifiant ? ")
        Mot_De_Passe = input("Mot de passe ? ")
        mdp_stockes.contenu[Site] = Entre(Site, Identifiant, Mot_De_Passe)
        sauvegarder_coffre(mdp_stockes, cle)

    if reponse == "chercher":
        Site = input("site ? ")
        if Site in mdp_stockes.contenu:
            print(f"identifiant: {mdp_stockes.contenu[Site].Identifiant}. \n Mot de passe: {mdp_stockes.contenu[Site].Mot_De_Passe}")
        else:
            print("Ce site n'est pas enregistré.")

    if reponse == "quitter":
        sauvegarder_coffre(mdp_stockes, cle)
        exit()