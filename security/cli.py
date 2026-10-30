#!/usr/bin/env python3
"""Local-only Cerato Network account recovery.

Run on the gateway under the dedicated service account (via sudo -u);
never map this script to an HTTP endpoint or system-wide privileged Web action.
"""
import argparse
import getpass
import os
import sqlite3
import sys
import time

from auth_store import AuthStore, HASHER, AuthError, validate_email, validate_password


def local_only():
    # A regular shell on the gateway is allowed; this is not a web command.
    if os.environ.get("REQUEST_METHOD") or os.environ.get("GATEWAY_INTERFACE"):
        sys.exit("Commande interdite dans un contexte CGI/Web.")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        sys.exit("Un terminal interactif local/SSH est requis.")


def main():
    parser = argparse.ArgumentParser(description="Cerato Network - comptes / accès de secours")
    parser.add_argument("--database", default="/var/lib/cerato-network-auth/accounts.sqlite3")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("bootstrap-token", help="Code de première configuration (15 minutes)")
    sub.add_parser("owner-status", help="État du compte principal, sans données sensibles")
    sub.add_parser("owner-reset", help="Modifier l'e-mail et le mot de passe principal par SSH")
    args = parser.parse_args()
    local_only()
    store = AuthStore(args.database)
    if args.command == "bootstrap-token":
        token = store.issue_bootstrap_token()
        print("Code de configuration valable 15 minutes et une seule fois :")
        print(token)
        print("Saisir ce code uniquement dans la page HTTPS Cerato Network.")
        return
    if args.command == "owner-status":
        print("Initialisé :" if store.is_initialized() else "Non initialisé")
        return
    if args.command == "owner-reset":
        if not store.is_initialized():
            sys.exit("Aucun propriétaire enregistré. Utiliser bootstrap-token.")
        with store._db() as db:
            row = db.execute("SELECT id,email FROM accounts WHERE role='owner'").fetchone()
            if row is None:
                sys.exit("Compte principal introuvable.")
            print("Compte principal :", row["email"])
            answer = input("Nouvel e-mail (laisser vide pour conserver) : ").strip()
            new_email = validate_email(answer) if answer else row["email"]
            p1 = getpass.getpass("Nouveau mot de passe (14 caractères min.) : ")
            p2 = getpass.getpass("Confirmer : ")
            if p1 != p2:
                sys.exit("Les mots de passe ne correspondent pas.")
            password_hash = HASHER.hash(validate_password(p1))
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE accounts SET email=?,passhash=? WHERE id=?", (new_email,password_hash,row["id"]))
            db.execute("DELETE FROM sessions WHERE account_id=?", (row["id"],))
            store._audit(db, "primary-owner-recovered-via-local-cli", row["id"], row["id"])
        print("Compte principal modifié. Toutes ses sessions ont été révoquées.")


if __name__ == "__main__":
    try:
        main()
    except (AuthError, sqlite3.Error) as exc:
        sys.exit(str(exc))
