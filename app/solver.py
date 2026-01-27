from typing import List, Tuple
import cmath
import math
import json

SUPERSCRIPTS = {
    "0": "⁰",
    "1": "¹",
    "2": "²",
    "3": "³",
    "4": "⁴",
    "5": "⁵",
    "6": "⁶",
    "7": "⁷",
    "8": "⁸",
    "9": "⁹",
    "-": "⁻",
}

def to_superscript(n: int) -> str:
    return "".join(SUPERSCRIPTS[c] for c in str(n))

def build_equation_pretty(degree: int, coeffs: List[float]) -> str:
    def near_zero(x: float) -> bool:
        return abs(x) < 1e-12

    def fmt(a: float) -> str:
        s = f"{a:.6f}".rstrip("0").rstrip(".")
        return s if s else "0"

    parts: List[str] = []
    for i, a in enumerate(coeffs):
        p = degree - i
        if near_zero(a):
            continue

        sign = "-" if a < 0 else "+"
        mag = abs(a)

        show_coeff = True
        if p > 0 and abs(mag - 1.0) < 1e-12:
            show_coeff = False

        term = ""
        if not parts:
            if a < 0:
                term += ". "
                term = "-"  # start with minus only
        else:
            term += f" {sign} "

        if show_coeff:
            term += fmt(mag)

        if p > 0:
            term += "x"
            if p > 1:
                term += to_superscript(p)

        parts.append(term)

    if not parts:
        return "f(x) = 0"
    return "f(x) = " + "".join(parts)


def eval_poly(coeffs: List[complex], z: complex) -> complex:
    y = 0j
    for a in coeffs:
        y = y * z + a
    return y


def solve_roots_durand_kerner(coeffs_real: List[float]) -> List[complex]:
    n = len(coeffs_real) - 1
    if n <= 0:
        return []

    lead = coeffs_real[0]
    if abs(lead) < 1e-14:
        return []

    a = [c / lead for c in coeffs_real]
    a_c = [complex(v, 0.0) for v in a]

    R = 0.6
    roots = [cmath.rect(R, 2.0 * math.pi * k / n) for k in range(n)]

    max_iter = 2500
    tol = 1e-12

    for _ in range(max_iter):
        max_change = 0.0
        for i in range(n):
            denom = 1 + 0j
            for j in range(n):
                if i != j:
                    denom *= (roots[i] - roots[j])
            if abs(denom) < 1e-14:
                denom = complex(1e-14, 0.0)

            p = eval_poly(a_c, roots[i])
            delta = p / denom
            roots[i] = roots[i] - delta
            max_change = max(max_change, abs(delta))
        if max_change < tol:
            break

    roots.sort(key=lambda z: (abs(z.imag) > 1e-8, z.real, z.imag))
    return roots


def auto_fit_y(coeffs: List[float], x_min: float, x_max: float) -> Tuple[float, float]:
    def eval_real(x: float) -> float:
        y = 0.0
        for a in coeffs:
            y = y * x + a
        return y

    N = 1000
    ymin = float("inf")
    ymax = float("-inf")

    for i in range(N):
        t = i / (N - 1)
        x = x_min + t * (x_max - x_min)
        y = eval_real(x)
        if math.isfinite(y):
            ymin = min(ymin, y)
            ymax = max(ymax, y)

    if not math.isfinite(ymin) or not math.isfinite(ymax) or ymin == ymax:
        return (-10.0, 10.0)

    pad = (ymax - ymin) * 0.10
    if pad <= 0:
        pad = 1.0
    return (ymin - pad, ymax + pad)


def roots_to_json(roots: List[complex]) -> str:
    payload = [{"re": float(z.real), "im": float(z.imag)} for z in roots]
    return json.dumps(payload)


def roots_from_json(s: str):
    return json.loads(s)
