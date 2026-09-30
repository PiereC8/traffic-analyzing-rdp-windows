# traffic-analyzing-rdp-windows
## Descripción

Este repositorio contiene el diseño conceptual de una solución orientada al análisis del tráfico de red y los registros de conexiones Remote Desktop Protocol en sistemas Windows.

La propuesta busca correlacionar información del tráfico RDP con eventos de Windows para identificar conexiones normales, intentos de fuerza bruta, accesos fuera de horario, uso de direcciones IP nuevas, credenciales posiblemente comprometidas y movimientos laterales.

## Estado del proyecto

El proyecto se encuentra en la etapa de diseño conceptual. El repositorio presenta la arquitectura propuesta, el flujo de funcionamiento, el diseño de las interfaces y la documentación académica.

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

- `docs`: informe final y presentación.
- `diseño/arquitectura`: diagramas de arquitectura y flujo.
- `diseño/interfaces`: diseños conceptuales de las interfaces.
- `evidencias`: capturas y descripción del prototipo.
- `referencias`: bibliografía y matriz de fuentes.

## Prototipo en Figma

[Insertar enlace de Figma]

## Fuentes bibliográficas

Los 40 archivos PDF utilizados en la revisión de literatura se encuentran organizados por subtema en Google Drive:

[Insertar enlace de Google Drive]

Por razones de derechos de autor, los artículos científicos no se publican directamente en este repositorio.

## Integrantes

- Piere Fabricio Carrillo Quenta (202407966)
- Dorian Avendaño Casapia
- Dana Franco Ramos
- Fabiana Del Pino
- Mattias Lupaca
- Leonel Rivera

## Curso y docente

- Curso: Sistemas Operativos I
- Docente: Dr. Renzo Alberto Taco Coayla
- Institución: Universidad Privada de Tacna
- Año: 2026
