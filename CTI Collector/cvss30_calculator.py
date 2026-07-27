"""
cvss_v30_calculator.py
--------------------------------------------------------------------
Tinh diem CVSS v3.0 tu vectorString (Base / Temporal / Environmental), 
theo dung cong thuc chinh thuc cua NVD/FIRST.
"""

import csv
import re
import sys
import argparse
from dataclasses import dataclass
from typing import Optional, Literal

Scope = Literal["UNCHANGED", "CHANGED"]
AV = Literal["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]
AC = Literal["LOW", "HIGH"]
PR = Literal["NONE", "LOW", "HIGH"]
UI = Literal["NONE", "REQUIRED"]
CI = Literal["NONE", "LOW", "HIGH"]

TemporalE = Literal["X", "U", "P", "F", "H"]
TemporalRL = Literal["X", "O", "T", "W", "U"]
TemporalRC = Literal["X", "U", "R", "C"]

Req = Literal["X", "L", "M", "H"]


@dataclass
class BaseMetricsV30:
    av: AV
    ac: AC
    pr: PR
    ui: UI
    s: Scope
    c: CI
    i: CI
    a: CI


@dataclass
class TemporalMetricsV30:
    e: TemporalE = "X"
    rl: TemporalRL = "X"
    rc: TemporalRC = "X"


@dataclass
class EnvironmentalMetricsV30:
    cr: Req = "X"
    ir: Req = "X"
    ar: Req = "X"

    mav: Optional[AV] = None
    mac: Optional[AC] = None
    mpr: Optional[PR] = None
    mui: Optional[UI] = None
    ms: Optional[Scope] = None
    mc: Optional[CI] = None
    mi: Optional[CI] = None
    ma: Optional[CI] = None


AV_WEIGHT = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20}
AC_WEIGHT = {"LOW": 0.77, "HIGH": 0.44}
UI_WEIGHT = {"NONE": 0.85, "REQUIRED": 0.62}
CIA_WEIGHT = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
PR_WEIGHT_UNCHANGED = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
PR_WEIGHT_CHANGED = {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50}
TEMPORAL_E_WEIGHT = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
TEMPORAL_RL_WEIGHT = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
TEMPORAL_RC_WEIGHT = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}
REQ_WEIGHT = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}

_AV_CODE = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
_AC_CODE = {"L": "LOW", "H": "HIGH"}
_PR_CODE = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_UI_CODE = {"N": "NONE", "R": "REQUIRED"}
_S_CODE = {"U": "UNCHANGED", "C": "CHANGED"}
_CIA_CODE = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_E_CODE = {"X": "X", "U": "U", "P": "P", "F": "F", "H": "H"}
_RL_CODE = {"X": "X", "O": "O", "T": "T", "W": "W", "U": "U"}
_RC_CODE = {"X": "X", "U": "U", "R": "R", "C": "C"}
_REQ_CODE = {"X": "X", "L": "L", "M": "M", "H": "H"}


def roundup_1(n: float) -> float:
    return (int(n * 10 + 0.9999999999)) / 10.0


def min_10(n: float) -> float:
    return min(n, 10.0)


def pr_weight(pr: PR, scope: Scope) -> float:
    return PR_WEIGHT_UNCHANGED[pr] if scope == "UNCHANGED" else PR_WEIGHT_CHANGED[pr]


def isc_base(m: BaseMetricsV30) -> float:
    c = CIA_WEIGHT[m.c]
    i = CIA_WEIGHT[m.i]
    a = CIA_WEIGHT[m.a]
    return 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)


def impact_subscore(m: BaseMetricsV30) -> float:
    isc = isc_base(m)
    if m.s == "UNCHANGED":
        return 6.42 * isc
    return 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)


def exploitability_subscore(m: BaseMetricsV30) -> float:
    return 8.22 * AV_WEIGHT[m.av] * AC_WEIGHT[m.ac] * pr_weight(m.pr, m.s) * UI_WEIGHT[m.ui]


def calculate_base_score(m: BaseMetricsV30) -> float:
    impact = impact_subscore(m)
    if impact <= 0:
        return 0.0

    exploitability = exploitability_subscore(m)
    if m.s == "UNCHANGED":
        score = min_10(impact + exploitability)
    else:
        score = min_10(1.08 * (impact + exploitability))

    return roundup_1(score)


def calculate_temporal_score(m: BaseMetricsV30, t: Optional[TemporalMetricsV30] = None) -> float:
    t = t or TemporalMetricsV30()
    base = calculate_base_score(m)
    if base <= 0:
        return 0.0

    e = TEMPORAL_E_WEIGHT[t.e]
    rl = TEMPORAL_RL_WEIGHT[t.rl]
    rc = TEMPORAL_RC_WEIGHT[t.rc]

    return roundup_1(base * e * rl * rc)


def _modified_metric(base_value, modified_value):
    return base_value if modified_value in (None, "X") else modified_value


def isc_modified(base: BaseMetricsV30, env: EnvironmentalMetricsV30) -> float:
    mc = CIA_WEIGHT[_modified_metric(base.c, env.mc)]
    mi = CIA_WEIGHT[_modified_metric(base.i, env.mi)]
    ma = CIA_WEIGHT[_modified_metric(base.a, env.ma)]

    cr = REQ_WEIGHT[env.cr]
    ir = REQ_WEIGHT[env.ir]
    ar = REQ_WEIGHT[env.ar]

    isc = 1.0 - (1.0 - mc * cr) * (1.0 - mi * ir) * (1.0 - ma * ar)
    return min(isc, 0.915)


def modified_impact_subscore(base: BaseMetricsV30, env: EnvironmentalMetricsV30) -> float:
    ms = _modified_metric(base.s, env.ms)
    isc = isc_modified(base, env)

    if ms == "UNCHANGED":
        return 6.42 * isc
    return 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)


def modified_exploitability_subscore(base: BaseMetricsV30, env: EnvironmentalMetricsV30) -> float:
    mav = _modified_metric(base.av, env.mav)
    mac = _modified_metric(base.ac, env.mac)
    mpr = _modified_metric(base.pr, env.mpr)
    mui = _modified_metric(base.ui, env.mui)
    ms = _modified_metric(base.s, env.ms)

    return 8.22 * AV_WEIGHT[mav] * AC_WEIGHT[mac] * pr_weight(mpr, ms) * UI_WEIGHT[mui]


def calculate_environmental_score(
    base: BaseMetricsV30,
    env: Optional[EnvironmentalMetricsV30] = None,
    temporal: Optional[TemporalMetricsV30] = None,
) -> float:
    env = env or EnvironmentalMetricsV30()
    temporal = temporal or TemporalMetricsV30()

    ms = _modified_metric(base.s, env.ms)
    m_impact = modified_impact_subscore(base, env)

    if m_impact <= 0:
        return 0.0

    m_exploitability = modified_exploitability_subscore(base, env)

    if ms == "UNCHANGED":
        inner = roundup_1(min_10(m_impact + m_exploitability))
    else:
        inner = roundup_1(min_10(1.08 * (m_impact + m_exploitability)))

    score = inner
    score *= TEMPORAL_E_WEIGHT[temporal.e]
    score *= TEMPORAL_RL_WEIGHT[temporal.rl]
    score *= TEMPORAL_RC_WEIGHT[temporal.rc]

    return roundup_1(score)


def calculate_cvss30(
    base: BaseMetricsV30,
    temporal: Optional[TemporalMetricsV30] = None,
    environmental: Optional[EnvironmentalMetricsV30] = None,
) -> dict:
    return {
        "base_score": calculate_base_score(base),
        "impact_subscore": round(impact_subscore(base), 1),
        "exploitability_subscore": round(exploitability_subscore(base), 1),
        "temporal_score": calculate_temporal_score(base, temporal),
        "environmental_score": calculate_environmental_score(base, environmental, temporal),
    }


_TOKEN_RE = re.compile(r"^([A-Za-z]+):([A-Za-z]+)$")


def parse_vector_string_v30(vector: str):
    if not vector or not isinstance(vector, str):
        raise ValueError(f"vectorString rong hoac khong hop le: {vector!r}")

    parts = [p for p in vector.strip().split("/") if p]
    fields = {}
    for part in parts:
        if part.upper().startswith("CVSS:"):
            continue  
        m = _TOKEN_RE.match(part)
        if not m:
            continue
        key, val = m.group(1).upper(), m.group(2).upper()
        fields[key] = val

    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [k for k in required if k not in fields]
    if missing:
        raise ValueError(f"Thieu metric bat buoc {missing} trong vectorString: {vector!r}")

    base = BaseMetricsV30(
        av=_AV_CODE[fields["AV"]],
        ac=_AC_CODE[fields["AC"]],
        pr=_PR_CODE[fields["PR"]],
        ui=_UI_CODE[fields["UI"]],
        s=_S_CODE[fields["S"]],
        c=_CIA_CODE[fields["C"]],
        i=_CIA_CODE[fields["I"]],
        a=_CIA_CODE[fields["A"]],
    )

    temporal = TemporalMetricsV30(
        e=_E_CODE.get(fields.get("E", "X"), "X"),
        rl=_RL_CODE.get(fields.get("RL", "X"), "X"),
        rc=_RC_CODE.get(fields.get("RC", "X"), "X"),
    )

    def _opt_av(v): return _AV_CODE[v] if v else None
    def _opt_ac(v): return _AC_CODE[v] if v else None
    def _opt_pr(v): return _PR_CODE[v] if v else None
    def _opt_ui(v): return _UI_CODE[v] if v else None
    def _opt_s(v): return _S_CODE[v] if v else None
    def _opt_cia(v): return _CIA_CODE[v] if v else None

    environmental = EnvironmentalMetricsV30(
        cr=_REQ_CODE.get(fields.get("CR", "X"), "X"),
        ir=_REQ_CODE.get(fields.get("IR", "X"), "X"),
        ar=_REQ_CODE.get(fields.get("AR", "X"), "X"),
        mav=_opt_av(fields.get("MAV")),
        mac=_opt_ac(fields.get("MAC")),
        mpr=_opt_pr(fields.get("MPR")),
        mui=_opt_ui(fields.get("MUI")),
        ms=_opt_s(fields.get("MS")),
        mc=_opt_cia(fields.get("MC")),
        mi=_opt_cia(fields.get("MI")),
        ma=_opt_cia(fields.get("MA")),
    )

    return base, temporal, environmental


def compute_from_vector_string_v30(vector: str, cve_id: str = "") -> dict:
    row = {
        "cve_id": cve_id,
        "vector_string": vector,
        "attack_vector": "", "attack_complexity": "", "privileges_required": "",
        "user_interaction": "", "scope": "",
        "confidentiality_impact": "", "integrity_impact": "", "availability_impact": "",
        "exploit_code_maturity": "", "remediation_level": "", "report_confidence": "",
        "base_score": "", "impact_subscore": "", "exploitability_subscore": "",
        "temporal_score": "", "environmental_score": "",
        "parse_error": "",
    }
    try:
        base, temporal, environmental = parse_vector_string_v30(vector)
    except ValueError as e:
        row["parse_error"] = str(e)
        return row

    scores = calculate_cvss30(base, temporal, environmental)

    row.update({
        "attack_vector": base.av,
        "attack_complexity": base.ac,
        "privileges_required": base.pr,
        "user_interaction": base.ui,
        "scope": base.s,
        "confidentiality_impact": base.c,
        "integrity_impact": base.i,
        "availability_impact": base.a,
        "exploit_code_maturity": temporal.e,
        "remediation_level": temporal.rl,
        "report_confidence": temporal.rc,
        "base_score": scores["base_score"],
        "impact_subscore": scores["impact_subscore"],
        "exploitability_subscore": scores["exploitability_subscore"],
        "temporal_score": scores["temporal_score"],
        "environmental_score": scores["environmental_score"],
    })
    return row


CSV_FIELDNAMES_V30 = [
    "cve_id", "vector_string",
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope",
    "confidentiality_impact", "integrity_impact", "availability_impact",
    "exploit_code_maturity", "remediation_level", "report_confidence",
    "base_score", "impact_subscore", "exploitability_subscore",
    "temporal_score", "environmental_score",
    "parse_error",
]


def process_csv_v30(input_csv: str, output_csv: str, vector_col: str = "cvss_v3_vector", id_col: str = "cve_id"):
    n_ok = n_err = n_skip = 0
    with open(input_csv, newline="", encoding="utf-8") as f_in, \
         open(output_csv, "w", newline="", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=CSV_FIELDNAMES_V30)
        writer.writeheader()

        for in_row in reader:
            vector = (in_row.get(vector_col) or "").strip()
            cve_id = (in_row.get(id_col) or "").strip()
            if not vector:
                n_skip += 1
                continue
            out_row = compute_from_vector_string_v30(vector, cve_id=cve_id)
            writer.writerow(out_row)
            if out_row["parse_error"]:
                n_err += 1
            else:
                n_ok += 1

    print(f"[CVSS v3.0] Da tinh xong: {n_ok} dong OK, {n_err} dong loi parse, {n_skip} dong bi bo qua")
    print(f"[CVSS v3.0] Ket qua luu tai: {output_csv}")


def process_vector_list_v30(vectors: list, output_csv: str):
    with open(output_csv, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_FIELDNAMES_V30)
        writer.writeheader()
        for i, v in enumerate(vectors):
            row = compute_from_vector_string_v30(v, cve_id=f"row_{i+1}")
            writer.writerow(row)
    print(f"[CVSS v3.0] Da tinh xong {len(vectors)} vectorString -> {output_csv}")


def _cli():
    parser = argparse.ArgumentParser(description="Tinh diem CVSS v3.0 tu vectorString, xuat CSV.")
    parser.add_argument("input", help="File CSV dau vao HOAC 1 vectorString don le")
    parser.add_argument("--out", required=True, help="Duong dan file CSV output")
    parser.add_argument("--vector-col", default="cvss_v3_vector", help="Ten cot chua vectorString trong CSV input")
    parser.add_argument("--id-col", default="cve_id", help="Ten cot chua CVE ID trong CSV input")
    args = parser.parse_args()

    if not args.input.lower().endswith(".csv"):
        process_vector_list_v30([args.input], args.out)
    else:
        process_csv_v30(args.input, args.out, vector_col=args.vector_col, id_col=args.id_col)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        _cli()
    else:
        demo_v30 = BaseMetricsV30(av="NETWORK", ac="LOW", pr="NONE", ui="NONE",
                                  s="UNCHANGED", c="HIGH", i="HIGH", a="HIGH")
        print("CVSS v3.0 demo (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H):")
        print(calculate_cvss30(demo_v30))
        print("\nSu dung thuc te: python cvss_v30_calculator.py data.csv --out result.csv")