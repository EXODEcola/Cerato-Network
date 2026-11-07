#!/usr/bin/env python3
"""Prepare a separate Python runtime for native accounts without altering the live Web.

--check  => read-only validation of existing runtime and OVH prerequisites
--install => create a NEW Python 3.12 venv, install pinned-range crypto wheels,
             verify Argon2id and AES-GCM as ceratonet, atomically move to place.

No system pip/apt, no Web service changes/restarts, no Nginx, accounts/DB,
WireGuard/NAT, SSH, IPv4 or VM Build. Does NOT activate native accounts.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

from prepare_native_auth_host import preflight as host_preflight

ROOT=Path("/opt/cerato-network")
DEST=ROOT/"native-auth-venv"
REQUIREMENTS=Path(__file__).resolve().parents[1]/"security/requirements.txt"
EXPECTED_REQUIREMENTS=b"argon2-cffi>=25.1,<26\ncryptography>=44,<48\n"
RUNUSER="/usr/sbin/runuser"
PYTHON="/usr/bin/python3"
ALLOWED_DISTS=frozenset({
    "argon2-cffi","argon2-cffi-bindings","cryptography","cffi","pycparser",
    "typing-extensions","pip","setuptools","wheel",
})
SMOKE=r"""
import json
import importlib.metadata as md
import secrets
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from packaging_not_needed import nop
"""  # intentionally replaced with a standard-library-only smoke below
SMOKE = r"""
import json, importlib.metadata as md, secrets, re
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def v(name):
    raw=md.version(name)
    parts=tuple(int(x) for x in re.findall(r"[0-9]+",raw)[:2])
    return raw,parts
argon,a=v('argon2-cffi')
crypto,c=v('cryptography')
assert (25,1)<=a<(26,0)
assert (44,0)<=c<(48,0)
p=PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1)
token=p.hash('cerato-runtime-self-test-only')
assert p.verify(token,'cerato-runtime-self-test-only')
key=AESGCM.generate_key(bit_length=256)
nonce=secrets.token_bytes(12)
aes=AESGCM(key)
cipher=aes.encrypt(nonce,b'cerato-auth-runtime-selftest',b'cerato')
assert aes.decrypt(nonce,cipher,b'cerato')==b'cerato-auth-runtime-selftest'
allow={'argon2-cffi','argon2-cffi-bindings','cryptography','cffi',
       'pycparser','typing-extensions','pip','setuptools','wheel'}
names={d.metadata['Name'].lower().replace('_','-') for d in md.distributions()}
assert names<=allow,names-allow
print(json.dumps({'argon2_version':argon,'cryptography_version':crypto,
                  'argon2id_checked':True,'aes_gcm_checked':True,
                  'approved_packages_only':True}))
"""

class RuntimePreparationError(ValueError):
    pass

def call(args,*,timeout=50,env=None,umask=None):
    kwargs={}
    if umask is not None:
        kwargs["preexec_fn"]=lambda:os.umask(umask)
    try:
        return subprocess.run(args,capture_output=True,text=True,
                              check=False,timeout=timeout,env=env,**kwargs)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimePreparationError("Commande de validation non disponible") from exc

def trusted_root():
    if ROOT.is_symlink() or not ROOT.is_dir():
        raise RuntimePreparationError("Répertoire Cerato inattendu")
    st=ROOT.stat()
    if st.st_uid!=0 or st.st_mode & (stat.S_IWGRP|stat.S_IWOTH):
        raise RuntimePreparationError("Répertoire Cerato modifiable par un tiers")
    if REQUIREMENTS.is_symlink() or not REQUIREMENTS.is_file():
        raise RuntimePreparationError("Liste de dépendances absente ou symbolique")
    if REQUIREMENTS.read_bytes()!=EXPECTED_REQUIREMENTS:
        raise RuntimePreparationError("Versions de sécurité non approuvées")
    if os.geteuid()!=0:
        raise RuntimePreparationError("Préparation réservée à root sur OVH")

def ensure_host():
    state=host_preflight()
    if (not state["storage_directory_ready"] or
            not state["systemd_dropin_present"] or
            not state["source_fingerprints_match"] or
            state["installed_version"]!="v0.1.2-beta.1"):
        raise RuntimePreparationError("Préparation du panneau existant incomplète")
    return state

def check_runtime(folder:Path):
    if folder.is_symlink() or not folder.is_dir():
        raise RuntimePreparationError("Environnement Python absent ou symbolique")
    meta=folder.stat()
    if meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o755:
        raise RuntimePreparationError("Permissions de l'environnement incorrectes")
    config=folder/"pyvenv.cfg"
    if config.is_symlink() or not config.is_file() or config.stat().st_uid!=0:
        raise RuntimePreparationError("Configuration du venv non approuvée")
    if "include-system-site-packages = false" not in config.read_text().lower():
        raise RuntimePreparationError("Le venv ne doit pas inclure les paquets système")
    binary=folder/"bin/python"
    if not binary.exists() or not binary.is_file():
        raise RuntimePreparationError("Interpréteur venv absent")
    user=pwd.getpwnam("ceratonet")
    if not user.pw_uid and not user.pw_gid:
        raise RuntimePreparationError("Compte Web inattendu")
    proc=call([RUNUSER,"-u","ceratonet","--",str(binary),"-I","-c",SMOKE],timeout=25)
    if proc.returncode:
        raise RuntimePreparationError("Autotest cryptographique sous ceratonet refusé")
    try:
        result=json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimePreparationError("Autotest Python non JSON") from exc
    if not (result.get("argon2id_checked") is True and
            result.get("aes_gcm_checked") is True and
            result.get("approved_packages_only") is True):
        raise RuntimePreparationError("Autotest cryptographique incomplet")
    return result

def state():
    trusted_root()
    ensure_host()
    if DEST.is_symlink():
        raise RuntimePreparationError("Environnement existant symbolique")
    if DEST.exists():
        detail=check_runtime(DEST)
        return {"status":"runtime_ready_inactive","runtime_created":False,
                "runtime":detail,"usable_by_web_user":True,
                "production_modified":False,"service_restarted":False,
                "network_modified":False,"accounts_created":False,
                "native_auth_activated":False}
    return {"status":"runtime_missing","runtime_created":False,
            "usable_by_web_user":False,
            "venv_module_available":call([PYTHON,"-m","venv","--help"]).returncode==0,
            "production_modified":False,"service_restarted":False,
            "network_modified":False,"accounts_created":False,
            "native_auth_activated":False}

def make_readable(root:Path):
    # Only the freshly created isolated environment contains files here.
    for folder,subdirs,files in os.walk(root,followlinks=False):
        for name in subdirs:
            path=Path(folder)/name
            if path.is_symlink():
                continue
            os.chmod(path,0o755,follow_symlinks=False)
        for name in files:
            path=Path(folder)/name
            if path.is_symlink():
                continue
            mode=path.stat().st_mode
            os.chmod(path,0o755 if mode & stat.S_IXUSR else 0o644,
                     follow_symlinks=False)
    os.chmod(root,0o755)

def install():
    previous=state()
    if previous["status"]=="runtime_ready_inactive":
        return previous
    if not previous.get("venv_module_available"):
        raise RuntimePreparationError(
            "python3-venv absent : aucun paquet système modifié")
    if not Path(RUNUSER).is_file() or not Path(PYTHON).is_file():
        raise RuntimePreparationError("Outil système absent")
    temp=Path(tempfile.mkdtemp(prefix=".native-auth-venv-staging.",dir=ROOT))
    os.chmod(temp,0o700)
    try:
        made=call([PYTHON,"-m","venv",str(temp)],timeout=80,umask=0o022)
        if made.returncode:
            raise RuntimePreparationError(
                "Création venv échouée : vérifier python3-venv, rien ne sera remplacé")
        python=temp/"bin/python"
        if not python.exists():
            raise RuntimePreparationError("Python isolé absent")
        env={**os.environ,
             "PIP_CONFIG_FILE":os.devnull,
             "PYTHONNOUSERSITE":"1",
             "PIP_DISABLE_PIP_VERSION_CHECK":"1",
             "PYTHONPATH":""}
        cmd=[str(python),"-m","pip","--isolated","install",
             "--disable-pip-version-check","--no-cache-dir","--no-input",
             "--only-binary=:all:","-r",str(REQUIREMENTS)]
        got=call(cmd,env=env,timeout=150,umask=0o022)
        if got.returncode:
            raise RuntimePreparationError(
                "Installation des roues Python approuvées impossible ; "
                "aucun changement du Python système")
        make_readable(temp)
        check_runtime(temp)
        # Fail closed if a concurrent operator has created the destination.
        if DEST.exists() or DEST.is_symlink():
            raise RuntimePreparationError("Environnement apparu pendant le staging")
        # Atomic rename within the same root-owned /opt/cerato-network.
        os.rename(temp,DEST)
        result=check_runtime(DEST)
        return {"status":"runtime_ready_inactive",
                "runtime_created":True,"runtime":result,
                "usable_by_web_user":True,
                "system_python_unchanged":True,
                "production_modified":False,"service_restarted":False,
                "network_modified":False,"accounts_created":False,
                "native_auth_activated":False}
    finally:
        if temp.exists():
            shutil.rmtree(temp)

def main():
    parser=argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check",action="store_true")
    modes.add_argument("--install",action="store_true")
    args=parser.parse_args()
    try:
        output=state() if args.check else install()
        print(json.dumps(output,sort_keys=True,ensure_ascii=False,indent=2))
    except (RuntimePreparationError,OSError,ValueError) as exc:
        parser.error(str(exc))

if __name__=="__main__":
    main()
