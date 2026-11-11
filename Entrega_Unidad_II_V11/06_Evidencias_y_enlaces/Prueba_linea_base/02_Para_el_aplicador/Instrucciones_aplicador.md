# Instrucciones para quien aplica la prueba

## Antes de empezar
1. Copie la carpeta `01_Materiales_participante` en la PC donde se hará la prueba. **No** copie esta carpeta
   (`02_Para_el_aplicador`) ni el informe, el Anexo Q, el Anexo S o la Tabla Q1: traen la respuesta.
2. Elija **una herramienta para todos** y anótela en el registro: Excel (recomendada, no requiere instalar nada)
   o Wireshark. Si un participante usa otra, anótelo en la columna Herramienta.
3. Tenga a la mano un cronómetro (el del celular sirve) y el archivo `Registro_de_tiempos.csv`.

## Con cada participante (una persona a la vez)
1. Explique la tarea en no más de 2 minutos leyendo `Enunciado_participante.txt`. No dé pistas ni la fórmula
   para convertir la hora (en Excel: `=(A2/86400)+DATE(1970;1;1)`; es parte del trabajo manual que se mide).
2. **Inicie el cronómetro** cuando la persona empiece a mirar los datos. **Deténgalo** cuando diga "listo".
3. Si pasan **15 minutos** sin respuesta, anote "No terminó".
4. No corrija ni muestre la respuesta hasta que termine todo el grupo.
5. Anote en el registro: participante (P1, P2, ...), herramienta, tiempo (min:s), si acertó y observaciones.

## Respuesta correcta (no la comparta con los participantes)
- El evento 4779 es de las 17:39:07 UTC y el cliente es 10.20.99.10.
- Flujos de esa IP: 5. Dentro de la ventana [−15 s; +5 s] cae **solo el flujo TCP 4 (puerto 49684, Δ = −8,6 s)**.
- El flujo TCP 3 (puerto 49683) está a −15,657 s: queda **fuera por 0,657 s**.
- Estado del vínculo: **PENDIENTE** (hay un candidato, pero el evento no trae el puerto de origen y no hay
  un 4624 de tipo 10 que abra una sesión confirmada).
- Se considera acierto: candidato = flujo TCP 4 y estado = pendiente.

## Al terminar
Calcule el tiempo mediano, el mínimo, el máximo y cuántos acertaron, y envíe el registro. No invente ni redondee
los tiempos: si el valor es chico también sirve, el informe reporta lo que se midió.
