from fastecdsa import curve
from fastecdsa.point import Point
import hashlib

curve = curve.secp256k1
G = curve.G                  # base generator
n = curve.q                  # curve order

def hash_to_scalar(data: bytes):
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % n

def derive_Gi(i: int) -> Point:
    s = hash_to_scalar(f"G{i}".encode())
    return s * G

def vector_commit(values, r, Q, H):
    C = None
    for i, v in enumerate(values, start=1):
        Gi = Q[i-1]
        term = v * Gi
        C = term if C is None else C + term

    C = C + r * H
    return C

def vector_verify(values, r, C, Q, H):
    C2 = None
    for i, v in enumerate(values, start=1):
        Gi = Q[i-1]
        term = v * Gi
        C2 = term if C2 is None else C2 + term
    C2 = C2 + r * H
    return C2 == C