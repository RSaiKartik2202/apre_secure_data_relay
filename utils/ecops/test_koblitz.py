import random
from koblitz import encode_reals, decode_reals


def approx_equal(a, b, eps=1e-6):
    return abs(a - b) < eps


def test_basic():
    params = [1.2345, 9.8765, 3.1415]
    P = encode_reals(params)
    recovered = decode_reals(P, len(params))

    assert all(approx_equal(a, b) for a, b in zip(params, recovered))
    print("Basic test passed")


def test_negative_values():
    params = [-2.3456, 0.0, 7.7777]
    P = encode_reals(params)
    recovered = decode_reals(P, len(params))

    assert all(approx_equal(a, b) for a, b in zip(params, recovered))
    print("Negative values test passed")


def test_random_cases():
    for _ in range(20):
        params = [random.uniform(-1000, 1000) for _ in range(3)]
        P = encode_reals(params)
        recovered = decode_reals(P, len(params))

        assert all(approx_equal(a, b) for a, b in zip(params, recovered))

    print("Random tests passed")


def test_determinism():
    # params = [4.5678, -9.1011, 12.1314, 5.123, 1.234]
    params = [4.5678, -9.1011, 12.1314, 5.123]
    P1 = encode_reals(params)
    P2 = encode_reals(params)

    assert P1.x == P2.x and P1.y == P2.y
    print("Determinism test passed")


if __name__ == "__main__":
    test_basic()
    test_negative_values()
    test_random_cases()
    test_determinism()
    print("\nAll tests passed successfully")
