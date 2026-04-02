from fastecdsa.curve import P384
from fastecdsa.point import Point
from fastecdsa.util import mod_sqrt

curve = P384
p = curve.p
a = curve.a
b = curve.b

KOBLITZ_K = 1000
PRECISION = 10**6
CHUNK_BITS = 48
CHUNK_MASK = (1 << CHUNK_BITS) - 1


def _encode_integer_list(int_list):
    m = 0
    for val in int_list:
        limit = 1 << (CHUNK_BITS - 1)
        if val >= limit or val < -limit:
            raise ValueError(f"Value {val} out of range for {CHUNK_BITS} bits")

        val &= CHUNK_MASK
        m = (m << CHUNK_BITS) | val

    if (m * KOBLITZ_K + (KOBLITZ_K - 1)) >= p:
        raise ValueError(f"Packed value {m} too large for field. Total bits: {m.bit_length()}")

    return m


def _decode_integer_list(m, count):
    vals = []
    SIGN_BIT_MASK = 1 << (CHUNK_BITS - 1)
    for _ in range(count):
        val = m & CHUNK_MASK
        if val & SIGN_BIT_MASK:
            val -= (1 << CHUNK_BITS)
        vals.append(val)
        m >>= CHUNK_BITS
    vals.reverse()
    return vals


def encode_reals(real_list):
    int_list = [int(round(r * PRECISION)) for r in real_list]
    m = _encode_integer_list(int_list)

    if m * KOBLITZ_K + (KOBLITZ_K - 1) >= p:
        raise ValueError("Packed value too large for curve field")

    for j in range(KOBLITZ_K):
        x = m * KOBLITZ_K + j
        rhs = (pow(x, 3, p) + a * x + b) % p
        roots = mod_sqrt(rhs, p)

        if roots is not None and len(roots) > 0:
            y = roots[0]
            
            # Verify it's an actual square root
            if (y * y) % p == rhs:
                if y % 2 != 0:
                    y = p - y
                return Point(x, y, curve)

    raise ValueError("Encoding failed; increase KOBLITZ_K")



def decode_reals(point, count):
    m = point.x // KOBLITZ_K
    int_list = _decode_integer_list(m, count)
    return [val / PRECISION for val in int_list]
