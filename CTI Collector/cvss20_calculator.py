"""
cvss_v2_calculator.py
--------------------------------------------------------------------
Tinh diem CVSS v2.0 tu vectorString (Base / Temporal / Environmental), 
theo dung cong thuc chinh thuc cua NVD/FIRST.
"""

import csv
import re
import sys
import argparse
from dataclasses import dataclass
from typing import Optional, Literal

AV2 = Literal["LOCAL", "ADJACENT_NETWORK", "NETWORK"]
AC2 = Literal["HIGH", "MEDIUM", "LOW"]
AU2 = Literal["MULTIPLE", "SINGLE", "NONE"]
CIA2 = Literal["NONE", "PARTIAL", "COMPLETE"]

E2 = Literal["UNPROVEN", "POC", "FUNCTIONAL", "HIGH", "ND"]
RL2 = Literal["OFFICIAL_FIX", "TEMPORARY_FIX", "WORKAROUND", "UNAVAILABLE", "ND"]
RC2 = Literal["UNCONFIRMED", "UNCORROBORATED", "CONFIRMED", "ND"]

CDP = Literal["NONE", "LOW", "LOW_MEDIUM", "MEDIUM_HIGH", "HIGH", "ND"]
TD = Literal["NONE", "LOW", "MEDIUM", "HIGH", "ND"]
Req2 = Literal["LOW", "MEDIUM", "HIGH", "ND"]


@dataclass
class BaseMetricsV2:
    av: AV2
    ac: AC2
    au: AU2
    c: CIA2
    i: CIA2
    a: CIA2


@dataclass
class TemporalMetricsV2:
    e: E2 = "ND"
    rl: RL2 = "ND"
    rc: RC2 = "ND"


@dataclass
class EnvironmentalMetricsV2:
    cdp: CDP = "ND"
    td: TD = "ND"
    cr: Req2 = "ND"
    ir: Req2 = "ND"
    ar: Req2 = "ND"


AV2_WEIGHT = {"LOCAL": 0.395, "ADJACENT_NETWORK": 0.646, "NETWORK": 1.0}
AC2_WEIGHT = {"HIGH": 0.35, "MEDIUM": 0.61, "LOW": 0.71}
AU2_WEIGHT = {"MULTIPLE": 0.45, "SINGLE": 0.56, "NONE": 0.704}
CIA2_WEIGHT = {"NONE": 0.0, "PARTIAL": 0.275, "COMPLETE": 0.660}

E2_WEIGHT = {"UNPROVEN": 0.85, "POC": 0.9, "FUNCTIONAL": 0.95, "HIGH": 1.0, "ND": 1.0}
RL2_WEIGHT = {"OFFICIAL_FIX": 0.87, "TEMPORARY_FIX": 0.90, "WORKAROUND": 0.95, "UNAVAILABLE": 1.0, "ND": 1.0}
RC2_WEIGHT = {"UNCONFIRMED": 0.90, "UNCORROBORATED": 0.95, "CONFIRMED": 1.0, "ND": 1.0}

CDP_WEIGHT = {"NONE": 0.0, "LOW": 0.1, "LOW_MEDIUM": 0.3, "MEDIUM_HIGH": 0.4, "HIGH": 0.5, "ND": 0.0}
TD_WEIGHT = {"NONE": 0.0, "LOW": 0.25, "MEDIUM": 0.75, "HIGH": 1.0, "ND": 1.0}
REQ2_WEIGHT = {"LOW": 0.5, "MEDIUM": 1.0, "HIGH": 1.51, "ND": 1.0}

_AV2_CODE = {"L": "LOCAL", "A": "ADJACENT_NETWORK", "N": "NETWORK"}
_AC2_CODE = {"H": "HIGH", "M": "MEDIUM", "L": "LOW"}
_AU2_CODE = {"M": "MULTIPLE", "S": "SINGLE", "N": "NONE"}
_CIA2_CODE = {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}

_E2_CODE = {"U": "UNPROVEN", "POC": "POC", "F": "FUNCTIONAL", "H": "HIGH", "ND": "ND"}
_RL2_CODE = {"OF": "OFFICIAL_FIX", "TF": "TEMPORARY_FIX", "W": "WORKAROUND", "U": "UNAVAILABLE", "ND": "ND"}
_RC2_CODE = {"UC": "UNCONFIRMED", "UR": "UNCORROBORATED", "C": "CONFIRMED", "ND": "ND"}

_CDP_CODE = {"N": "NONE", "L": "LOW", "LM": "LOW_MEDIUM", "MH": "MEDIUM_HIGH", "H": "HIGH", "ND": "ND"}
_TD_CODE = {"N": "NONE", "L": "LOW", "M": "MEDIUM", "H": "HIGH", "ND": "ND"}
_REQ2_CODE = {"L": "LOW", "M": "MEDIUM", "H": "HIGH", "ND": "ND"}


def round_1(n: float) -> float:
    return round(n + 1e-9, 1)


def impact_v2(m: BaseMetricsV2) -> float:
    c = CIA2_WEIGHT[m.c]
    i = CIA2_WEIGHT[m.i]
    a = CIA2_WEIGHT[m.a]
    return 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))


def exploitability_v2(m: BaseMetricsV2) -> float:
    return 20 * AC2_WEIGHT[m.ac] * AU2_WEIGHT[m.au] * AV2_WEIGHT[m.av]


def _f_impact(impact: float) -> float:
    return 0.0 if impact == 0 else 1.176


def calculate_base_score_v2(m: BaseMetricsV2) -> float:
    impact = impact_v2(m)
    exploitability = exploitability_v2(m)
    base = (0.6 * impact + 0.4 * exploitability - 1.5) * _f_impact(impact)
    return round_1(base)


def calculate_temporal_score_v2(m: BaseMetricsV2, t: Optional[TemporalMetricsV2] = None) -> float:
    t = t or TemporalMetricsV2()
    base = calculate_base_score_v2(m)
    score = base * E2_WEIGHT[t.e] * RL2_WEIGHT[t.rl] * RC2_WEIGHT[t.rc]
    return round_1(score)


def adjusted_impact_v2(m: BaseMetricsV2, env: EnvironmentalMetricsV2) -> float:
    cr = REQ2_WEIGHT[env.cr]
    ir = REQ2_WEIGHT[env.ir]
    ar = REQ2_WEIGHT[env.ar]
    c = CIA2_WEIGHT[m.c]
    i = CIA2_WEIGHT[m.i]
    a = CIA2_WEIGHT[m.a]
    val = 10.41 * (1 - (1 - c * cr) * (1 - i * ir) * (1 - a * ar))
    return min(10.0, val)


def calculate_adjusted_temporal_v2(
    m: BaseMetricsV2, t: Optional[TemporalMetricsV2], env: EnvironmentalMetricsV2
) -> float:
    t = t or TemporalMetricsV2()
    adj_impact = adjusted_impact_v2(m, env)
    exploitability = exploitability_v2(m)
    adj_base = round_1((0.6 * adj_impact + 0.4 * exploitability - 1.5) * _f_impact(adj_impact))
    return round_1(adj_base * E2_WEIGHT[t.e] * RL2_WEIGHT[t.rl] * RC2_WEIGHT[t.rc])


def calculate_environmental_score_v2(
    m: BaseMetricsV2,
    t: Optional[TemporalMetricsV2] = None,
    env: Optional[EnvironmentalMetricsV2] = None,
) -> float:
    env = env or EnvironmentalMetricsV2()
    adjusted_temporal = calculate_adjusted_temporal_v2(m, t, env)
    cdp = CDP_WEIGHT[env.cdp]
    td = TD_WEIGHT[env.td]
    score = (adjusted_temporal + (10 - adjusted_temporal) * cdp) * td
    return round_1(score)


def calculate_cvss2(
    m: BaseMetricsV2,
    t: Optional[TemporalMetricsV2] = None,
    env: Optional[EnvironmentalMetricsV2] = None,
) -> dict:
    return {
        "base_score": calculate_base_score_v2(m),
        "impact_subscore": round(impact_v2(m), 1),
        "exploitability_subscore": round(exploitability_v2(m), 1),
        "temporal_score": calculate_temporal_score_v2(m, t),
        "environmental_score": calculate_environmental_score_v2(m, t, env),
    }


_TOKEN_RE_V2 = re.compile(r"^([A-Za-z]+):([A-Za-z]+)$")


def parse_vector_string_v2(vector: str):
    if not vector or not isinstance(vector, str):
        raise ValueError(f"vectorString CVSSv2 rong hoac khong hop le: {vector!r}")

    v = vector.strip()
    if v.startswith("(") and v.endswith(")"):
        v = v[1:-1]
    v = re.sub(r"^CVSS2#", "", v, flags=re.IGNORECASE)
    v = re.sub(r"^CVSS:2\.0/?", "", v, flags=re.IGNORECASE)

    parts = [p for p in v.split("/") if p]
    fields = {}
    for part in parts:
        m = _TOKEN_RE_V2.match(part)
        if not m:
            continue
        key, val = m.group(1).upper(), m.group(2).upper()
        fields[key] = val

    required = ["AV", "AC", "AU", "C", "I", "A"]
    missing = [k for k in required if k not in fields]
    if missing:
        raise ValueError(f"Thieu metric bat buoc {missing} trong vectorString CVSSv2: {vector!r}")

    base = BaseMetricsV2(
        av=_AV2_CODE[fields["AV"]],
        ac=_AC2_CODE[fields["AC"]],
        au=_AU2_CODE[fields["AU"]],
        c=_CIA2_CODE[fields["C"]],
        i=_CIA2_CODE[fields["I"]],
        a=_CIA2_CODE[fields["A"]],
    )

    temporal = TemporalMetricsV2(
        e=_E2_CODE.get(fields.get("E", "ND"), "ND"),
        rl=_RL2_CODE.get(fields.get("RL", "ND"), "ND"),
        rc=_RC2_CODE.get(fields.get("RC", "ND"), "ND"),
    )

    environmental = EnvironmentalMetricsV2(
        cdp=_CDP_CODE.get(fields.get("CDP", "ND"), "ND"),
        td=_TD_CODE.get(fields.get("TD", "ND"), "ND"),
        cr=_REQ2_CODE.get(fields.get("CR", "ND"), "ND"),
        ir=_REQ2_CODE.get(fields.get("IR", "ND"), "ND"),
        ar=_REQ2_CODE.get(fields.get("AR", "ND"), "ND"),
    )

    return base, temporal, environmental


def compute_from_vector_string_v2(vector: str, cve_id: str = "") -> dict:
    row = {
        "cve_id": cve_id,
        "vector_string": vector,
        "access_vector": "", "access_complexity": "", "authentication": "",
        "confidentiality_impact": "", "integrity_impact": "", "availability_impact": "",
        "exploitability": "", "remediation_level": "", "report_confidence": "",
        "base_score": "", "impact_subscore": "", "exploitability_subscore": "",
        "temporal_score": "", "environmental_score": "",
        "parse_error": "",
    }
    try:
        base, temporal, environmental = parse_vector_string_v2(vector)
    except ValueError as e:
        row["parse_error"] = str(e)
        return row

    scores = calculate_cvss2(base, temporal, environmental)

    row.update({
        "access_vector": base.av,
        "access_complexity": base.ac,
        "authentication": base.au,
        "confidentiality_impact": base.c,
        "integrity_impact": base.i,
        "availability_impact": base.a,
        "exploitability": temporal.e,
        "remediation_level": temporal.rl,
        "report_confidence": temporal.rc,
        "base_score": scores["base_score"],
        "impact_subscore": scores["impact_subscore"],
        "exploitability_subscore": scores["exploitability_subscore"],
        "temporal_score": scores["temporal_score"],
        "environmental_score": scores["environmental_score"],
    })
    return row


CSV_FIELDNAMES_V2 = [
    "cve_id", "vector_string",
    "access_vector", "access_complexity", "authentication",
    "confidentiality_impact", "integrity_impact", "availability_impact",
    "exploitability", "remediation_level", "report_confidence",
    "base_score", "impact_subscore", "exploitability_subscore",
    "temporal_score", "environmental_score",
    "parse_error",
]


def process_csv_v2(input_csv: str, output_csv: str, vector_col: str = "cvss_v2_vector", id_col: str = "cve_id"):
    n_ok = n_err = n_skip = 0
    with open(input_csv, newline="", encoding="utf-8") as f_in, \
         open(output_csv, "w", newline="", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=CSV_FIELDNAMES_V2)
        writer.writeheader()

        for in_row in reader:
            vector = (in_row.get(vector_col) or "").strip()
            cve_id = (in_row.get(id_col) or "").strip()
            if not vector:
                n_skip += 1
                continue
            out_row = compute_from_vector_string_v2(vector, cve_id=cve_id)
            writer.writerow(out_row)
            if out_row["parse_error"]:
                n_err += 1
            else:
                n_ok += 1

    print(f"[CVSS v2.0] Da tinh xong: {n_ok} dong OK, {n_err} dong loi parse, {n_skip} dong bi bo qua")
    print(f"[CVSS v2.0] Ket qua luu tai: {output_csv}")


def process_vector_list_v2(vectors: list, output_csv: str):
    with open(output_csv, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_FIELDNAMES_V2)
        writer.writeheader()
        for i, v in enumerate(vectors):
            row = compute_from_vector_string_v2(v, cve_id=f"row_{i+1}")
            writer.writerow(row)
    print(f"[CVSS v2.0] Da tinh xong {len(vectors)} vectorString -> {output_csv}")


def _cli():
    parser = argparse.ArgumentParser(description="Tinh diem CVSS v2.0 tu vectorString, xuat CSV.")
    parser.add_argument("input", help="File CSV dau vao HOAC 1 vectorString don le")
    parser.add_argument("--out", required=True, help="Duong dan file CSV output")
    parser.add_argument("--vector-col", default="cvss_v2_vector", help="Ten cot chua vectorString trong CSV input")
    parser.add_argument("--id-col", default="cve_id", help="Ten cot chua CVE ID trong CSV input")
    args = parser.parse_args()

    if not args.input.lower().endswith(".csv"):
        process_vector_list_v2([args.input], args.out)
    else:
        process_csv_v2(args.input, args.out, vector_col=args.vector_col, id_col=args.id_col)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _cli()
    else:
        demo_v2 = BaseMetricsV2(av="NETWORK", ac="LOW", au="NONE", c="NONE", i="NONE", a="COMPLETE")
        print("CVSS v2.0 demo (AV:N/AC:L/Au:N/C:N/I:N/A:C):")
        print(calculate_cvss2(demo_v2))
        print("\nSu dung thuc te: python cvss_v2_calculator.py data.csv --out result.csv")