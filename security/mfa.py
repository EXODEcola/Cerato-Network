"""TOTP primitives for Cerato Network.

This module is independent of the web server. Enrollment must remain provisional
until the owner confirms a valid code; persist seeds in the private auth database
and block owner/admin login until MFA is implemented end-to-end.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

def generate_secret() -> str:
    # 160 bits / RFC6238 compatible with most authenticator apps.
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

def _decode(secret: str) -> bytes:
    if not isinstance(secret,str) or len(secret) > 128:
        raise ValueError("Secret TOTP invalide")
    s=secret.upper().strip()
    raw=base64.b32decode(s + "=" * (-len(s) % 8),casefold=True)
    if len(raw)<16:
        raise ValueError("Secret TOTP trop court")
    return raw

def code_for_counter(secret: str, counter: int, digits: int = 6) -> str:
    if not isinstance(counter,int) or counter < 0 or digits not in (6,8):
        raise ValueError("Paramètres TOTP invalides")
    digest=hmac.new(_decode(secret),struct.pack(">Q",counter),hashlib.sha1).digest()
    offset=digest[-1] & 15
    value=(struct.unpack(">I",digest[offset:offset+4])[0] & 0x7fffffff) % (10**digits)
    return str(value).zfill(digits)

def verify(secret: str, entered: str, *, at: int | None = None,
           skew: int = 1, last_counter: int = -1) -> int | None:
    """Return matched counter to persist atomically for replay protection.

    A caller must lock the account row and store this counter before accepting
    the request; otherwise two concurrent submissions could reuse one code.
    """
    if not isinstance(entered,str) or not entered.isascii() or not entered.isdigit() or len(entered)!=6:
        return None
    now=int(time.time()) if at is None else int(at)
    if now < 0 or skew not in (0,1):
        return None
    counter=now//30
    for step in range(max(0,counter-skew),counter+skew+1):
        if step <= last_counter:
            continue
        if hmac.compare_digest(code_for_counter(secret,step),entered):
            return step
    return None

def enrollment_uri(secret: str, email: str, issuer: str = "Cerato Network") -> str:
    # Use this URI only in a protected owner/admin enrollment flow.
    _decode(secret)
    label=quote(issuer + ":" + email,safe="")
    return ("otpauth://totp/"+label+"?secret="+quote(secret,safe="")+
            "&issuer="+quote(issuer,safe="")+"&algorithm=SHA1&digits=6&period=30")

def recovery_codes(count: int = 8):
    if not 4 <= count <= 16:
        raise ValueError("Nombre incorrect")
    raw=[secrets.token_urlsafe(12) for _ in range(count)]
    hashed=[hashlib.sha256(v.encode()).hexdigest() for v in raw]
    return raw, hashed

def consume_recovery(value: str, hashes: list[str]) -> tuple[bool,list[str]]:
    candidate=hashlib.sha256(value.encode("utf8")).hexdigest()
    found=False
    left=[]
    for digest in hashes:
        match=hmac.compare_digest(candidate,digest)
        if match and not found:
            found=True
        else:
            left.append(digest)
    return found,left
