# Anexo N · Verificación de cobertura del corpus

## 1. Para qué sirve

No sustituye una revisión sistemática. Comprueba una sola cosa: que la identificación inicial de fuentes
no dependió de una recomendación única, porque una búsqueda independiente por subtema recupera los mismos
trabajos. Se ejecuta **una vez**, se registra la fecha y se informa el resultado, sea bueno o malo.

## 2. Ecuaciones por subtema

Se ejecutan en Google Académico e IEEE Xplore, con los filtros por defecto y sin restricción de año.
Entre paréntesis va lo que devuelve cada una.

| Subtema | Ecuación |
|---|---|
| S1 Fundamentos de RDP | `("remote desktop protocol" OR "remote desktop connection") AND (architecture OR security)` |
| S2 Tráfico RDP | `("remote desktop" OR RDP) AND (traffic OR bandwidth OR latency) AND encrypted` |
| S3 Registros y correlación | `"event log" AND (RDP OR "remote desktop") AND (correlation OR timeline)` |
| S4 Seguridad y amenazas | `(RDP OR "remote desktop") AND ("brute force" OR "password spraying" OR "lateral movement")` |
| S5 Herramientas y monitoreo | `(SIEM OR Wazuh OR Suricata OR Sysmon) AND (RDP OR "remote desktop") AND detection` |
| S6 Detección y forense | `"digital forensics" AND Windows AND (RDP OR "remote desktop") AND artifacts` |

## 3. Qué se registra por búsqueda

1. Base (Google Académico o IEEE) y fecha.
2. Ecuación exacta, copiada tal cual se ejecutó.
3. Número de resultados que anuncia la base.
4. De los 83 documentos del corpus, **cuántos aparecen entre los primeros 100 resultados** de su subtema.
5. Identificadores (primer autor y año) de los localizados.
6. Observaciones: si la base cambió el orden, si hubo que añadir un sinónimo, etc.

El registro se hace en `Anexo_N_Resultados.csv`.

## 4. Cómo se cierra

- **Umbral sugerido:** si al menos **40 de los 83** documentos aparecen en los primeros 100 de su subtema,
  la cobertura se declara suficiente.
- Si el número es menor, **se informa igual**: «la verificación recuperó N de 83; el resto se incorporó por
  la cadena de referencias». Eso sigue siendo una respuesta honesta y defendible.

## 5. Si no se ejecuta

No pasa nada: §1.4 ya declara la limitación y el trabajo no queda debilitado. Simplemente no se puede afirmar
lo que no se midió.
