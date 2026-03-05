from fastecdsa.curve import P256
from fastecdsa.point import Point
import hashlib
import secrets

curve = P256                # secp256r1
G = P256.G                  # base generator
n = P256.q                  # curve order

# ----------------------------------------------------
# Hash → scalar (mod curve order)
# ----------------------------------------------------
def hash_to_scalar(data: bytes):
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, "big") % n


# ----------------------------------------------------
# Derive generator Gi = Hash(i) * G
# ----------------------------------------------------
def derive_Gi(i: int) -> Point:
    s = hash_to_scalar(f"G{i}".encode())
    return s * G


# ----------------------------------------------------
# Derive fixed H = Hash("H") * G
# ----------------------------------------------------
H = hash_to_scalar(b"H") * G


# ----------------------------------------------------
# Commit:  C = Σ vi*Gi + rH
# ----------------------------------------------------
def vector_commit(values,r):
    C = None
    for i, v in enumerate(values, start=1):
        Gi = derive_Gi(i)
        term = v * Gi
        C = term if C is None else C + term

    C = C + r * H
    return C


# ----------------------------------------------------
# Verify: recompute C' and compare
# ----------------------------------------------------
def vector_verify(values, r, C):
    C2 = None
    for i, v in enumerate(values, start=1):
        Gi = derive_Gi(i)
        term = v * Gi
        C2 = term if C2 is None else C2 + term
    C2 = C2 + r * H
    return C2 == C


# ----------------------------------------------------
# Example use
# ----------------------------------------------------
values = [5, 12, 20]
secret_key=secrets.randbelow(n)
C = vector_commit(values,secret_key)

print("Commitment:")
print("  C.x =", C.x)
print("  C.y =", C.y)

print("Valid?:", vector_verify(values, secret_key, C))