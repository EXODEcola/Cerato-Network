"""Encrypt Cerato Network MFA seeds at rest using AES-256-GCM.

Key is stored independently from the SQLite database, 0600 and owned by the
service user. On production deployments the key path must be backed up
separately, outside the public web root and outside Git.
"""
from __future__ import annotations
import base64
import os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretBoxError(RuntimeError):
    pass


class SecretBox:
    def __init__(self, key_path: str | Path):
        self.path = Path(key_path)
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if self.path.is_symlink():
            raise SecretBoxError("Clé de chiffrement symbolique refusée.")
        # Generate only if the host has no existing key; never silently
        # overwrite a key (doing so would permanently orphan MFA seeds).
        if not self.path.exists():
            try:
                fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            except FileExistsError:
                fd=None
            if fd is not None:
                try:
                    key=secrets.token_bytes(32)
                    with os.fdopen(fd,"wb") as out:
                        out.write(key)
                        out.flush()
                        os.fsync(out.fileno())
                except BaseException:
                    self.path.unlink(missing_ok=True)
                    raise
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                    or info.st_mode & 0o077):
                raise SecretBoxError("Clé de chiffrement non privée (owner, chmod 600 requis).")
            key=os.read(fd,33)
        finally:
            os.close(fd)
        if len(key)!=32:
            raise SecretBoxError("Clé de chiffrement incorrecte (32 octets requis).")
        self._aes=AESGCM(key)

    def seal(self, plaintext: str, account_id: int) -> str:
        if not isinstance(plaintext,str) or not isinstance(account_id,int) or account_id<1:
            raise SecretBoxError("Impossible de chiffrer le secret.")
        nonce=secrets.token_bytes(12)
        aad=("cerato:mfa:"+str(account_id)).encode("ascii")
        encrypted=self._aes.encrypt(nonce,plaintext.encode("utf8"),aad)
        return "enc:v1:"+base64.urlsafe_b64encode(nonce+encrypted).decode("ascii")

    def open(self, token: str, account_id: int) -> str:
        if (not isinstance(token,str) or not token.startswith("enc:v1:")
                or len(token)>1024 or not isinstance(account_id,int) or account_id<1):
            raise SecretBoxError("Secret MFA chiffré invalide.")
        try:
            raw=base64.b64decode(token[7:],altchars=b"-_",validate=True)
            if len(raw)<29:
                raise ValueError("Format trop court")
            aad=("cerato:mfa:"+str(account_id)).encode("ascii")
            return self._aes.decrypt(raw[:12],raw[12:],aad).decode("utf8")
        except (ValueError,UnicodeError,Exception) as exc:
            # Do not leak the GCM tag, key or plaintext in an error response.
            raise SecretBoxError("Impossible de déchiffrer le secret MFA.") from exc
