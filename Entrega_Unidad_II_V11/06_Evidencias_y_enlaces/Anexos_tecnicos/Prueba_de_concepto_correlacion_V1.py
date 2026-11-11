"""Prueba de concepto de la regla de correlación (Unidad II, Anexo S).

Aplica a la captura real del Anexo Q la regla del informe (sección 6.5):
un evento de Windows se asocia con los flujos TCP 3389 que parten de su misma IP de origen
y empiezan en la ventana [t - 15 s, t + 5 s]. Estados: confirmado, pendiente, sin asociación.

  - Solo un 4624 de tipo 10 puede dar un vínculo confirmado (con un único candidato; si el evento
    trae puerto de origen útil, debe coincidir).
  - Un 4779/4778 corrobora una transición de sesión: con candidatos queda pendiente.
  - Dos o más candidatos sin criterio de desempate: pendiente (ambigüedad conservada).
  - Sin IP de origen, sin candidatos o con un tipo de inicio de sesión ajeno a RDP: sin asociación.

Uso:  python -I Prueba_de_concepto_correlacion_V1.py [carpeta_de_datos]
Entradas: 02_eventos.csv y 03_syn_tcp.csv (verificadas contra 05_manifest_sha256.csv).
Salida:   Anexo_S_Resultado_prueba_de_concepto.csv junto a este archivo.
"""
import csv, hashlib, io, re, sys
from datetime import datetime, timezone
from pathlib import Path

AQUI = Path(__file__).resolve().parent
DATOS = Path(sys.argv[1]) if len(sys.argv) > 1 else AQUI.parent.parent / "08_evidencia_preliminar"
ANTES, DESPUES = 15.0, 5.0          # ventana [t - 15 s, t + 5 s]


def a_epoch(texto):
    """ISO 8601 con fracciones de hasta 7 dígitos -> segundos desde 1970 (UTC)."""
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z", texto)
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return base + float("0." + (m.group(2) or "0"))


def verificar_manifiesto():
    esperado = {}
    with io.open(DATOS / "05_manifest_sha256.csv", encoding="utf-8-sig", newline="") as f:
        for fila in csv.DictReader(f):
            esperado[fila["Archivo"]] = fila["SHA256"].lower()
    ok = True
    for nombre in ("02_eventos.csv", "03_syn_tcp.csv"):
        h = hashlib.sha256((DATOS / nombre).read_bytes()).hexdigest()
        coincide = h == esperado.get(nombre)
        ok &= coincide
        print(f"  integridad {nombre}: {'coincide' if coincide else 'NO COINCIDE'} ({h[:12]}…)")
    return ok


def leer_flujos():
    flujos = []
    with io.open(DATOS / "03_syn_tcp.csv", encoding="utf-8-sig") as f:
        lineas = [l.rstrip("\r\n") for l in f if l.strip()]
    for linea in lineas[1:]:
        campos = [c.strip('"') for c in linea.split("\\")]
        flujos.append({"t": float(campos[0]), "src": campos[1], "dst": campos[2],
                       "sport": campos[3], "dport": campos[4], "stream": campos[5]})
    return flujos


def campo(mensaje, *etiquetas):
    for et in etiquetas:
        m = re.search(re.escape(et) + r":\s*([^\r\n]*)", mensaje)
        if m:
            return m.group(1).strip()
    return ""


def leer_eventos():
    eventos = []
    with io.open(DATOS / "02_eventos.csv", encoding="utf-8-sig", newline="") as f:
        for fila in csv.DictReader(f):
            msg = fila["Message"]
            eventos.append({
                "id": fila["Id"], "registro": fila["RecordId"], "t": a_epoch(fila["HoraUTC"]),
                "hora": fila["HoraUTC"],
                "tipo": campo(msg, "Tipo de inicio de sesión"),
                "ip": campo(msg, "Dirección de cliente", "Dirección de red de origen"),
                "puerto": campo(msg, "Puerto de origen"),
            })
    return eventos


def correlacionar(ev, flujos):
    """Devuelve (estado, candidatos, motivo)."""
    if ev["id"] == "4624" and ev["tipo"] != "10":
        return "sin asociación", [], f"4624 de tipo {ev['tipo']}: no es un inicio de sesión RDP interactivo"
    if ev["ip"] in ("", "-"):
        return "sin asociación", [], "el evento no trae IP de origen"
    cand = [f for f in flujos if f["src"] == ev["ip"] and f["dport"] == "3389"
            and ev["t"] - ANTES <= f["t"] <= ev["t"] + DESPUES]
    if not cand:
        return "sin asociación", [], "ningún flujo TCP 3389 de esa IP en la ventana"
    if len(cand) > 1:
        return "pendiente", cand, "dos o más candidatos sin criterio de desempate; se conservan todos"
    if ev["id"] == "4624" and ev["tipo"] == "10":
        if ev["puerto"] not in ("", "-") and ev["puerto"] != cand[0]["sport"]:
            return "sin asociación", [], "el puerto de origen del evento no coincide con el flujo"
        return "confirmado", cand, "un candidato; 4624 tipo 10" + (" y puerto coincidente" if ev["puerto"] not in ("", "-") else "")
    return "pendiente", cand, "un candidato, pero el evento corrobora una transición, falta 4624 tipo 10 y el puerto de origen"


def filas_resultado(ev, flujos, etiqueta):
    estado, cand, motivo = correlacionar(ev, flujos)
    filas = []
    for fl in flujos:
        if fl["src"] != ev["ip"]:
            continue
        d = fl["t"] - ev["t"]
        dentro = ev["t"] - ANTES <= fl["t"] <= ev["t"] + DESPUES
        filas.append([etiqueta, f"{ev['id']}/{ev['registro']}", ev["hora"], f"TCP {fl['stream']} / {fl['sport']}",
                      f"{d:+.3f}".replace(".", ","), "dentro" if dentro else "fuera", estado, motivo])
    if not filas:
        filas.append([etiqueta, f"{ev['id']}/{ev['registro']}", ev["hora"], "-", "-", "-", estado, motivo])
    return estado, filas


def prueba_sintetica():
    """Tres casos sintéticos que ejercitan los tres estados (no son datos del laboratorio)."""
    base = 1_800_000_000.0
    fl = lambda dt, sp, n: {"t": base + dt, "src": "10.20.10.10", "dst": "10.20.20.10", "sport": sp, "dport": "3389", "stream": n}
    caso = lambda i, t, tipo, puerto="-": {"id": "4624", "registro": i, "t": base + t, "hora": "sintético",
                                         "tipo": tipo, "ip": "10.20.10.10", "puerto": puerto}
    casos = [
        ("S-1 confirmado", caso("S1", 10, "10", "50001"), [fl(8, "50001", "0")], "confirmado"),
        ("S-2 pendiente (dos candidatos)", caso("S2", 10, "10"), [fl(2, "50002", "0"), fl(6, "50003", "1")], "pendiente"),
        ("S-3 sin asociación (flujo fuera de la ventana)", caso("S3", 10, "10"), [fl(-30, "50004", "0")], "sin asociación"),
    ]
    resultados = []
    for nombre, ev, flujos, esperado in casos:
        estado, _, _ = correlacionar(ev, flujos)
        resultados.append((nombre, esperado, estado, "CUMPLE" if estado == esperado else "NO CUMPLE"))
    return resultados


def main():
    print("Prueba de concepto de correlación — datos:", DATOS)
    if not verificar_manifiesto():
        sys.exit("Los archivos de entrada no coinciden con el manifiesto SHA-256.")
    flujos, eventos = leer_flujos(), leer_eventos()
    print(f"  {len(flujos)} flujos TCP y {len(eventos)} eventos de Windows leídos")
    salida = [["Origen", "Evento / registro", "Hora UTC del evento", "Flujo", "Δ (s) flujo − evento", "Ventana [−15; +5]", "Estado del vínculo", "Motivo"]]
    for ev in sorted(eventos, key=lambda e: e["t"]):
        estado, filas = filas_resultado(ev, flujos, "captura real")
        salida += filas
        print(f"  evento {ev['id']}/{ev['registro']} -> {estado}")
    print("Prueba sintética de los tres estados (no son datos del laboratorio):")
    for nombre, esperado, estado, veredicto in prueba_sintetica():
        print(f"  {nombre}: esperado {esperado}, obtenido {estado} -> {veredicto}")
        salida.append(["sintético", nombre, "-", "-", "-", "-", estado, f"esperado {esperado}: {veredicto}"])
    destino = AQUI / "Anexo_S_Resultado_prueba_de_concepto.csv"
    with io.open(destino, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f, delimiter=";", lineterminator="\r\n").writerows(salida)
    print("guardado:", destino)


if __name__ == "__main__":
    main()
