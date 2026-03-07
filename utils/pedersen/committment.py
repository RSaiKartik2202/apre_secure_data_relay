from fastecdsa import curve
from fastecdsa.point import Point
from decimal import Decimal
import hashlib
import secrets

curve = curve.secp256k1
G = curve.G                  # base generator
n = curve.q                  # curve order
PRECISION = 10**6

def hash_to_scalar(data: bytes):
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % n

def derive_Gi(i: int) -> Point:
    s = hash_to_scalar(f"G{i}".encode())
    return s * G

H = hash_to_scalar(b"H") * G

def vector_commit(values,r):
    C = None
    for i, v in enumerate(values, start=1):
        Gi = derive_Gi(i)
        v_int = int(Decimal(str(v)) * PRECISION)
        term = v_int * Gi
        C = term if C is None else C + term

    C = C + r * H
    return C

def vector_verify(values, r, C):
    C2 = None
    for i, v in enumerate(values, start=1):
        Gi = derive_Gi(i)
        v_int = int(Decimal(str(v)) * PRECISION)
        term = v_int * Gi
        C2 = term if C2 is None else C2 + term
    C2 = C2 + r * H
    return C2 == C

values = [5.235, 12.146, 20.457]
secret_key=secrets.randbelow(n)
C = vector_commit(values,secret_key)

print("Commitment:")
print("  C.x =", C.x)
print("  C.y =", C.y)

print("Valid?:", vector_verify(values, secret_key, C))
