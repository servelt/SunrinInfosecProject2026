"""CVSS v3.1 base score from a vector string, computed here rather than taken from a model.

Formulas and constants: FIRST, "CVSS v3.1 Specification Document", section 7 (base metric
equations), section 7.4 (metric values) and Appendix A (Roundup).  The qualitative rating is
section 5: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.  GitHub's
advisory form uses the same four levels and calls Medium "Moderate".
"""

from __future__ import annotations

import math

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse(vector: str) -> dict[str, str]:
    text = vector.strip()
    if text.startswith("CVSS:3.1/"):
        text = text[len("CVSS:3.1/"):]
    elif text.startswith("CVSS:"):
        raise ValueError(f"only CVSS 3.1 vectors are scored here: {vector}")
    metrics = dict(part.split(":", 1) for part in text.split("/") if ":" in part)
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise ValueError(f"vector misses base metrics {missing}: {vector}")
    if metrics["S"] not in ("U", "C"):
        raise ValueError(f"S must be U or C: {vector}")
    for name in ("AV", "AC", "UI", "C", "I", "A"):
        if metrics[name] not in _WEIGHTS[name]:
            raise ValueError(f"{name}:{metrics[name]} is not a valid value")
    if metrics["PR"] not in _PR["U"]:
        raise ValueError(f"PR:{metrics['PR']} is not a valid value")
    return {m: metrics[m] for m in REQUIRED}


def roundup(value: float) -> float:
    """Appendix A: the smallest number, to one decimal place, >= value (float-safe)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse(vector)
    iss = 1 - (1 - _WEIGHTS["C"][m["C"]]) * (1 - _WEIGHTS["I"][m["I"]]) * (1 - _WEIGHTS["A"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = (8.22 * _WEIGHTS["AV"][m["AV"]] * _WEIGHTS["AC"][m["AC"]] * _PR[m["S"]][m["PR"]]
                      * _WEIGHTS["UI"][m["UI"]])
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def rating(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def normalise(vector: str) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in parse(vector).items())
