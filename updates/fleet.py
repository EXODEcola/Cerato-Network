"""Signed-release fleet state machine for Cerato Network.

Agents PULL verified updates; the gateway never runs arbitrary SSH commands on
remote nodes. This is the offline state/authorization core; HTTP integration
and the agent-side updater still require integration and end-to-end testing.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

NAME=re.compile(r"^[a-z][a-z0-9-]{0,39}$")
VERSION=re.compile(r"^v\d+\.\d+\.\d+(?:-(?:beta|rc)\.\d+)?$")
HASH=re.compile(r"^[a-f0-9]{64}$")


class FleetError(Exception):
    pass


def _digest(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _open(path):
    conn=sqlite3.connect(path,timeout=10)
    conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


class Fleet:
    def __init__(self, path):
        self.path=Path(path)
        if self.path.is_symlink():
            raise FleetError("Base symbolique interdite")
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with _open(self.path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS agents(
                  name TEXT PRIMARY KEY,
                  token_hash TEXT NOT NULL UNIQUE,
                  installed_version TEXT,
                  desired_version TEXT,
                  status TEXT NOT NULL DEFAULT 'pending',
                  last_seen INTEGER,
                  last_error TEXT,
                  updated INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS releases(
                  version TEXT PRIMARY KEY,
                  sha256 TEXT NOT NULL,
                  artifact TEXT NOT NULL,
                  manifest BLOB NOT NULL,
                  signature BLOB NOT NULL,
                  staged_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fleet_audit(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  created INTEGER NOT NULL,
                  event TEXT NOT NULL,
                  target TEXT
                );
            """)
        os.chmod(self.path,0o600)

    def enroll(self, name: str):
        """Call only from an authenticated gateway owner/admin enrollment flow.

        Raw token returned once to node bootstrap; persist only SHA-256.
        """
        if not isinstance(name,str) or not NAME.fullmatch(name):
            raise FleetError("Nom de machine invalide")
        token=secrets.token_urlsafe(48)
        now=int(time.time())
        with _open(self.path) as db:
            if db.execute("SELECT 1 FROM agents WHERE name=?",(name,)).fetchone():
                raise FleetError("Machine déjà enregistrée")
            db.execute("INSERT INTO agents(name,token_hash,updated) VALUES(?,?,?)",
                       (name,_digest(token),now))
            db.execute("INSERT INTO fleet_audit(created,event,target) VALUES(?,?,?)",
                       (now,"agent-enrolled",name))
        return {"name":name,"token":token}

    def _agent(self, token: str):
        if not isinstance(token,str) or not 40<=len(token)<=256:
            raise FleetError("Agent non autorisé")
        with _open(self.path) as db:
            row=db.execute("SELECT name FROM agents WHERE token_hash=?",(_digest(token),)).fetchone()
        if not row:
            raise FleetError("Agent non autorisé")
        return row["name"]

    def stage_verified_release(self, manifest: bytes, signature: bytes, public_key: Path):
        """Validate signature BEFORE storing anything as a distributable release."""
        import sys
        import tempfile
        import subprocess
        if len(manifest)>32_768 or len(signature)>256:
            raise FleetError("Manifeste ou signature trop volumineux")
        with tempfile.TemporaryDirectory(prefix="cerato-fleet-verify-") as directory:
            p=Path(directory)
            (p/"manifest").write_bytes(manifest)
            (p/"sig").write_bytes(signature)
            try:
                result=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-rawin",
                          "-inkey",str(public_key),"-in",str(p/"manifest"),
                          "-sigfile",str(p/"sig")],capture_output=True,timeout=12)
            except (OSError,subprocess.TimeoutExpired) as exc:
                raise FleetError("Vérification indisponible") from exc
            if result.returncode!=0:
                raise FleetError("Signature invalide")
        try:
            obj=json.loads(manifest)
        except (ValueError,UnicodeError):
            raise FleetError("Manifeste invalide")
        if not isinstance(obj,dict) or obj.get("product")!="cerato-network" or obj.get("schema")!=1:
            raise FleetError("Format de release invalide")
        version=obj.get("version")
        digest=obj.get("sha256")
        asset=obj.get("artifact")
        if not (isinstance(version,str) and VERSION.fullmatch(version) and
                isinstance(digest,str) and HASH.fullmatch(digest) and
                asset=="cerato-network-release.zip"):
            raise FleetError("Version ou archive invalide")
        with _open(self.path) as db:
            db.execute("INSERT OR REPLACE INTO releases(version,sha256,artifact,manifest,signature,staged_at) VALUES(?,?,?,?,?,?)",
                       (version,digest,asset,manifest,signature,int(time.time())))
        return version

    def schedule(self, version: str, *, ready_gateway_version: str, names=None):
        """Called by privileged central controller AFTER healthcheck of gateway release.

        Returns count of queued nodes; offline nodes remain pending.
        """
        if version!=ready_gateway_version or not VERSION.fullmatch(str(version)):
            raise FleetError("Version passerelle non vérifiée")
        now=int(time.time())
        with _open(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM releases WHERE version=?",(version,)).fetchone():
                raise FleetError("Release non signée / non préparée")
            if names is None:
                names=[r["name"] for r in db.execute("SELECT name FROM agents")]
            if not isinstance(names,(tuple,list)) or not all(isinstance(n,str) and NAME.fullmatch(n) for n in names):
                raise FleetError("Liste de machines invalide")
            affected=0
            for name in names:
                result=db.execute(
                    "UPDATE agents SET desired_version=?,status='queued',updated=?,last_error=NULL "
                    "WHERE name=? AND (installed_version IS NULL OR installed_version!=?)",
                    (version,now,name,version))
                affected+=result.rowcount
            db.execute("INSERT INTO fleet_audit(created,event,target) VALUES(?,?,?)",
                       (now,"fleet-scheduled",version))
            return affected

    def poll(self, token: str):
        """Authenticated node reads its intended release (no command execution)."""
        name=self._agent(token)
        now=int(time.time())
        with _open(self.path) as db:
            db.execute("UPDATE agents SET last_seen=? WHERE name=?",(now,name))
            row=db.execute("SELECT desired_version,installed_version,status FROM agents WHERE name=?",(name,)).fetchone()
            if not row or not row["desired_version"] or row["installed_version"]==row["desired_version"]:
                return {"update":False}
            release=db.execute("SELECT manifest,signature FROM releases WHERE version=?",(row["desired_version"],)).fetchone()
            if not release:
                raise FleetError("Release introuvable")
            db.execute("UPDATE agents SET status='offered' WHERE name=?",(name,))
            return {"update":True,"version":row["desired_version"],
                    "manifest":json.loads(release["manifest"]),
                    "signature":bytes(release["signature"]).hex()}

    def report(self, token: str, version: str, success: bool, error: str = ""):
        name=self._agent(token)
        if not isinstance(version,str) or not VERSION.fullmatch(version) or not isinstance(success,bool):
            raise FleetError("Résultat invalide")
        now=int(time.time())
        with _open(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT desired_version FROM agents WHERE name=?",(name,)).fetchone()
            if not row or row["desired_version"]!=version:
                raise FleetError("Version non demandée à cet agent")
            state="updated" if success else "failed"
            db.execute("UPDATE agents SET installed_version=CASE WHEN ? THEN ? ELSE installed_version END,"
                       "status=?,last_error=?,last_seen=?,updated=? WHERE name=?",
                       (int(success),version,state,("" if success else str(error)[:240]),now,now,name))
            db.execute("INSERT INTO fleet_audit(created,event,target) VALUES(?,?,?)",
                       (now,"agent-"+state,name))

    def overview(self):
        """Must only be returned to authenticated owner/admin API callers."""
        with _open(self.path) as db:
            rows=db.execute("SELECT name,installed_version,desired_version,status,last_seen,last_error "
                            "FROM agents ORDER BY name").fetchall()
            return [dict(row) for row in rows]
