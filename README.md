# traffic-analyzing-rdp-windows
## Descripción

Este repositorio contiene el diseño conceptual de una solución orientada al análisis del tráfico de red y los registros de conexiones Remote Desktop Protocol en sistemas Windows.

La propuesta busca correlacionar información del tráfico RDP con eventos de Windows para identificar conexiones normales, intentos de fuerza bruta, accesos fuera de horario, uso de direcciones IP nuevas, credenciales posiblemente comprometidas y movimientos laterales.

## Estado del proyecto

El proyecto se encuentra en la etapa de diseño (Unidad II); la implementación se realiza en la Unidad III. El repositorio presenta la arquitectura propuesta, el flujo de funcionamiento, el diseño de las interfaces y la documentación académica.

No contiene actualmente una implementación funcional ni un sistema desplegado.

## Objetivo general

Diseñar una solución para recopilar, correlacionar y analizar el tráfico y los registros de conexiones RDP en Windows, con la finalidad de detectar comportamientos anómalos, calcular el nivel de riesgo y presentar alertas explicables.

## Funciones propuestas

- Recolección de tráfico de conexiones RDP.
- Obtención de registros de seguridad de Windows.
- Correlación de eventos por usuario, dirección IP, equipo y horario.
- Detección de conexiones anómalas.
- Puntuación de riesgo de 0 a 100.
- Visualización de conexiones, usuarios y alertas.
- Generación de reportes.
- Apoyo al análisis forense y respuesta a incidentes.

## Herramientas consideradas

- Wireshark
- PowerShell
- Sysmon
- Windows Event Forwarding
- Elastic Stack, Splunk o Microsoft Sentinel
- Figma
- GitHub

## Estructura del repositorio

- `docs`: informe de la Unidad I (PMI).
- `Entrega_Unidad_II_V13`: entrega de la Unidad II.
  - `01_Informe`: informe de diseño en Word y PDF (versión 13).
  - `02_Presentacion`: presentación de sustentación en PPTX y PDF (versión 12, seis partes).
  - `03_Diagramas`: diagramas de arquitectura, flujo, secuencia, datos, despliegue, topología y seguridad.
  - `04_Prototipo`: capturas del prototipo de Figma y recorrido de los casos de diseño.
  - `05_Fuentes`: referencias APA 7, concordancia citas-referencias y registro de verificación.
  - `06_Evidencias_y_enlaces`: anexos técnicos editables (CSV, scripts de la prueba de correlación y del ensayo de recuperación) y prueba de línea base.
  - `08_evidencia_preliminar`: captura del laboratorio, eventos exportados y manifiesto SHA-256.
- `Sitio-Web`: sitio del proyecto con la descarga de los documentos.

## Prototipo en Figma

- [Recorrido de los tres casos](https://www.figma.com/proto/h8yUohZU6NVHWTLkb2AYWn?node-id=21-227)
- [Vistas editables](https://www.figma.com/design/h8yUohZU6NVHWTLkb2AYWn?node-id=21-227)

El prototipo representa escenarios simulados; el tablero funcional se implementa en la Unidad III.

## Fuentes bibliográficas

Los 83 archivos PDF utilizados en la revisión de literatura se encuentran organizados por subtema en Google Drive:

[Carpeta del proyecto en Google Drive](https://drive.google.com/drive/folders/1Vg1ablKRYeeNLUIzI-96Wys8z7t1Pn-Q?usp=drive_link)

Por razones de derechos de autor, los artículos científicos no se publican directamente en este repositorio. Las capturas de pantalla de pruebas que muestran rutas locales se conservan solo en Drive.

## Integrantes

- Piere Fabricio Carrillo Quenta (2024079966)
- Dorian Avendaño Casapia
- Dana Milagros Franco Ramos     (2024016556)
- Fabiana Del Pino
- Mattias Lupaca
- Leonel Rivera

## Curso y docente

- Curso: Sistemas Operativos I
- Docente: Dr. Renzo Alberto Taco Coayla
- Institución: Universidad Privada de Tacna
- Año: 2026
