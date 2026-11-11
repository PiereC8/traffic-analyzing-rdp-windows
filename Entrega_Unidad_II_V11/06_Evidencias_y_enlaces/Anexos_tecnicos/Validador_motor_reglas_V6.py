# -*- coding: utf-8 -*-
"""Validador funcional del motor de reglas RDP (Unidad II, V6).

Implementa la fórmula del §10.2 del informe y valida con casos sintéticos:
  Puntaje = min(100, min(50, R-01 + R-02) + R-03 + R-04 + R-05 + R-06 + R-07)

Uso:  python Validador_motor_reglas_V6.py
Salida: Anexo_O_Validacion_motor_reglas_V6.csv (junto al script)
"""
import csv
import os
from datetime import datetime, timedelta

# ---- ventanas y pesos declarados en el informe -------------------------
W_FAIL = 300       # R-01 / R-02: 5 min
W_SCAN = 900       # R-06: 15 min
W_SPRAY = 600      # R-07: 10 min
HIST_DAYS = 14     # R-03: historial de 14 días
HOURS = (8, 18)    # R-04: horario autorizado
P = {"R-01": 25, "R-02": 30, "R-03": 15, "R-04": 10, "R-05": 15, "R-06": 15, "R-07": 55}


def ev(t, eid, ip, account="lab-07", host="WIN-RDP", logon_type=None, priv=False):
    return {"t": t, "eid": eid, "ip": ip, "account": account, "host": host,
            "logon_type": logon_type, "priv": priv}


def _fails(events):
    return [e for e in events if e["eid"] == 4625 and e["logon_type"] == 3]


def _success(events):
    return [e for e in events if e["eid"] == 4624 and e["logon_type"] == 10]


def rule_r01(events):
    f = _fails(events)
    for a in f:
        sel = [b for b in f if b["ip"] == a["ip"] and b["account"] == a["account"]
               and b["host"] == a["host"] and 0 <= (b["t"] - a["t"]).total_seconds() <= W_FAIL]
        if len(sel) >= 5:
            return True
    return False


def rule_r02(events):
    s = _success(events)
    for ok in s:
        prior = [b for b in _fails(events) if b["ip"] == ok["ip"] and b["account"] == ok["account"]
                 and b["host"] == ok["host"] and 0 <= (ok["t"] - b["t"]).total_seconds() <= W_FAIL]
        if len(prior) >= 5:
            return True
    return False


def rule_r03(events, history):
    return any(ok["ip"] not in history.get(ok["account"], set()) for ok in _success(events))


def rule_r04(events):
    return any(not (HOURS[0] <= ok["t"].hour < HOURS[1]) for ok in _success(events))


def rule_r05(events):
    return any(e["priv"] for e in events)


def rule_r06(events):
    ips = {}
    for ok in _success(events):
        ips.setdefault(ok["account"], []).append(ok)
    for acc, lst in ips.items():
        for a in lst:
            near = {b["ip"] for b in lst if abs((b["t"] - a["t"]).total_seconds()) <= W_SCAN}
            if len(near) >= 3:
                return True
    return False


def rule_r07(events):
    f = _fails(events)
    for a in f:
        sel = [b for b in f if b["ip"] == a["ip"] and 0 <= (b["t"] - a["t"]).total_seconds() <= W_SPRAY]
        if len(sel) >= 8 and len({b["account"] for b in sel}) >= 5:
            return True
    return False


def score(events, history=None):
    history = history or {}
    flags = {
        "R-01": rule_r01(events),
        "R-02": rule_r02(events),
        "R-03": rule_r03(events, history),
        "R-04": rule_r04(events),
        "R-05": rule_r05(events),
        "R-06": rule_r06(events),
        "R-07": rule_r07(events),
    }
    raw = sum(P[k] for k, v in flags.items() if v)
    total = min(100, min(50, (P["R-01"] if flags["R-01"] else 0) + (P["R-02"] if flags["R-02"] else 0))
                + sum(P[k] for k in ("R-03", "R-04", "R-05", "R-06", "R-07") if flags[k]))
    return flags, raw, total


def severity(total):
    if total >= 75:
        return "Crítica"
    if total >= 50:
        return "Alta"
    if total >= 25:
        return "Media"
    return "Baja"


def correlate(success_t, flows):
    """Ventana [t-15 s, t+5 s]; dos candidatos sin desempate => pendiente."""
    cand = [f for f in flows if -15 <= (f["t"] - success_t).total_seconds() <= 5]
    if len(cand) == 1:
        return "confirmado"
    if len(cand) == 0:
        return "sin asociación"
    if len({f["port"] for f in cand}) == 1:
        return "confirmado"
    return "pendiente"


T0 = datetime(2026, 11, 10, 22, 9, 55)


def main():
    cases = []

    # CD-01 / AL-018: 5 fallos, éxito a los 5 min, IP nueva, fuera de horario y 4672
    e = [ev(T0 + timedelta(seconds=20 * i), 4625, "10.20.10.10", logon_type=3) for i in range(5)]
    e.append(ev(T0 + timedelta(seconds=300), 4624, "10.20.10.10", logon_type=10))
    e.append(ev(T0 + timedelta(seconds=301), 4672, "10.20.10.10", priv=True))
    cases.append(("AL-018 / CD-01", "Éxito tras 5 fallos, IP nueva, fuera de horario, 4672", e,
                  {"lab-07": {"10.20.10.99"}}, 90))

    # CD-02: acceso normal en horario, IP conocida, sin privilegios
    e = [ev(datetime(2026, 11, 10, 10, 0, 5), 4624, "10.20.10.10", logon_type=10)]
    cases.append(("CD-02", "Acceso normal en horario laboral", e, {"lab-07": {"10.20.10.10"}}, 0))

    # CD-03: correlación ambigua (se evalúa aparte)
    ok_t = datetime(2026, 11, 10, 11, 0, 0)
    flows = [{"t": ok_t + timedelta(seconds=-2), "port": 50111},
             {"t": ok_t + timedelta(seconds=-1), "port": 50112}]
    state = correlate(ok_t, flows)
    cases.append(("CD-03", "Dos flujos compatibles: el vínculo debe quedar pendiente", [], {}, 0))

    # B1: cuatro fallos (no dispara R-01)
    e = [ev(T0 + timedelta(seconds=15 * i), 4625, "10.20.10.10", logon_type=3) for i in range(4)]
    cases.append(("B-01", "Cuatro fallos: por debajo del umbral", e, {}, 0))

    # B2: cinco fallos sin éxito
    e = [ev(T0 + timedelta(seconds=15 * i), 4625, "10.20.10.10", logon_type=3) for i in range(5)]
    cases.append(("B-02", "Cinco fallos sin éxito posterior", e, {}, 25))

    # B3: password spraying (8 fallos a 5 cuentas en 10 min)
    e = []
    for i, acc in enumerate(["u1", "u2", "u3", "u4", "u5", "u1", "u2", "u3"]):
        e.append(ev(T0 + timedelta(seconds=40 * i), 4625, "10.20.10.77", account=acc, logon_type=3))
    cases.append(("B-03", "Password spraying: 8 fallos a 5 cuentas", e, {}, 55))

    # B4: tope del puntaje (R-01+R-02 topados a 50, más R-07 = 55)
    e = [ev(T0 + timedelta(seconds=20 * i), 4625, "10.20.10.10", logon_type=3) for i in range(5)]
    e.append(ev(T0 + timedelta(seconds=300), 4624, "10.20.10.10", logon_type=10))
    for i, acc in enumerate(["u1", "u2", "u3", "u4", "u5", "u1", "u2", "u3"]):
        e.append(ev(T0 + timedelta(seconds=400 + 40 * i), 4625, "10.20.10.10", account=acc, logon_type=3))
    cases.append(("B-04", "Tope de 100 con R-01+R-02 topados y R-07", e, {}, 100))

    rows = []
    print(f"{'Caso':<18}{'R-01':>6}{'R-02':>6}{'R-03':>6}{'R-04':>6}{'R-05':>6}{'R-06':>6}{'R-07':>6}{'Puntaje':>9}{'Esperado':>10}  Veredicto")
    for name, desc, events, hist, expected in cases:
        flags, raw, total = score(events, hist)
        ok = "CUMPLE" if total == expected else "NO CUMPLE"
        print(f"{name:<18}" + "".join(f"{('S' if flags[k] else '-'):>6}" for k in P)
              + f"{total:>9}{expected:>10}  {ok}")
        rows.append({
            "Caso": name, "Descripcion": desc,
            **{k: ("Sí" if flags[k] else "No") for k in P},
            "Suma bruta": raw, "Puntaje": total, "Severidad": severity(total),
            "Esperado": expected, "Veredicto": ok,
            "Estado de correlación": state if name == "CD-03" else "no aplica",
        })

    print(f"\nCD-03 correlación ambigua: {state} (esperado: pendiente)")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "Anexo_O_Validacion_motor_reglas_V6.csv")
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=";")
        w.writeheader()
        w.writerows(rows)
    print("guardado:", out)


if __name__ == "__main__":
    main()
