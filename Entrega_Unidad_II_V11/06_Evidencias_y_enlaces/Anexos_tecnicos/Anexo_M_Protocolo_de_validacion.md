# Anexo M · Plan de verificación de adquisición para la Unidad III

Este plan desarrolla los casos CP-01, CP-02 y CP-03 de las Tablas 24 y 25. La implementación utilizará el entorno aislado y las cuentas de laboratorio autorizadas definidos en el diseño. El Anexo Q conserva la captura existente como antecedente documental.

## Preparación

El responsable del entorno verifica el inventario, la autorización de los equipos, el aislamiento de red y la sincronización de los relojes con una referencia común. El responsable de instrumentación registra las versiones del sistema operativo y de las herramientas y comprueba que los canales de auditoría requeridos estén disponibles.

## Casos de aceptación

| Caso | Qué se verificará | Evidencia y condición de aceptación |
|---|---|---|
| CP-01 | Adquisición de eventos y metadatos de red durante los escenarios controlados del plan. | Registro de Security, captura, bitácora y manifiesto. Se identifican eventos pertinentes a cada escenario y se conserva el origen, el destino y la hora. El desfase medido entre VM es de hasta 2 s y los archivos coinciden con el manifiesto. |
| CP-02 | Transiciones de inicio, desconexión, reconexión y cierre previstas en la bitácora. | Se contrastan Security y Terminal Services. Los registros 4778 y 4779 se cotejan con LSM 25 y 24 cuando haya una clave de sesión verificable. |
| CP-03 | Asociación fiable de proceso y conservación de casos ambiguos. | Se cotejan equipo, origen, tiempo y puerto si consta. Los candidatos indistinguibles se conservan como pendientes y el dictamen explica la evidencia disponible. |

El equipo registrará la versión, el resultado esperado y el resultado observado en la plantilla adjunta. Las condiciones detalladas de aceptación constan en el informe. Los archivos y sus marcas temporales se conservarán con su procedencia.
