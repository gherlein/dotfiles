from decimal import Decimal, getcontext, ROUND_DOWN


def arctan_inv(n: int) -> Decimal:
    """Return arctan(1/n) using the Taylor series:
    arctan(x) = x - x^3/3 + x^5/5 - ...
    """
    x = Decimal(1) / Decimal(n)
    total = Decimal(0)
    x_power = x          # x^(2k+1), starts at x^1
    sign = 1
    k = 0
    while True:
        term = sign * x_power / (2 * k + 1)
        if term == 0:
            break
        total += term
        sign = -sign
        x_power *= x * x
        k += 1
    return total


def compute_pi(places: int = 100) -> Decimal:
    """Machin's formula: pi = 16*arctan(1/5) - 4*arctan(1/239)"""
    getcontext().prec = places + 20   # extra guard digits
    pi = 16 * arctan_inv(5) - 4 * arctan_inv(239)
    # Trim back to exactly `places` digits after the decimal point.
    quantum = Decimal(1).scaleb(-places)
    return pi.quantize(quantum, rounding=ROUND_DOWN)


if __name__ == "__main__":
    print(compute_pi(100))
