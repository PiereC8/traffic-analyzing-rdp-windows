# Anexo M · Protocolo de validación y línea base

La Unidad II entrega un diseño. Este procedimiento puede ejecutarse después, con autorización y cuentas ficticias. La revisión visual de Figma se registra en el Anexo J.

## 1. Preparación

1. En Hyper-V crea un conmutador **privado** denominado `U2-Piloto`. Conecta solo las VM CLI-RDP y WIN-RDP. Asigna `10.20.99.10/24` al cliente y `10.20.99.20/24` al host. Deja puerta de enlace y DNS en blanco. Este segmento temporal permite probar adquisición con dos VM. Los segmentos y reglas de las figuras 5–7 corresponden a la arquitectura completa.
2. En WIN-RDP, habilita Escritorio remoto con NLA, autoriza una cuenta de laboratorio sin privilegios de administrador y limita la regla entrante de Escritorio remoto al origen `10.20.99.10`. Deshabilita otras reglas entrantes para 3389 que permitan orígenes más amplios. Configura confianza en el certificado antes de la conexión. Instala TShark y Npcap desde medios autorizados.
3. En `secpol.msc`, habilita **Auditar inicio de sesión** para éxito y error y **Auditar otros eventos de inicio/cierre de sesión** para éxito. En el host, comprueba la política con `auditpol /get /category:*`. Registra la compilación de Windows y la versión de TShark.
4. Verifica la hora de ambas VM y documenta el desfase. La marca de tiempo de los paquetes y de Security se tomará en WIN-RDP. Conserva UTC y comprueba que el desvío de las VM sea ≤ 2 s si se comparan sus bitácoras. Desde el cliente comprueba `Test-NetConnection 10.20.99.20 -Port 3389` antes de iniciar la captura para evitar confundir ese sondeo con un intento.

## 2. Adquisición

Abre PowerShell como administrador en WIN-RDP. En la primera consola, ejecuta lo siguiente. Sustituye el número de interfaz por el de la NIC conectada a U2-Piloto.

```powershell
$carpeta = Join-Path $env:USERPROFILE 'U2-Piloto'
New-Item -ItemType Directory -Path $carpeta -Force | Out-Null
$tshark = Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'
& $tshark -v | Out-File (Join-Path $carpeta '00_version_tshark.txt')
& $tshark -D
$interfaz = Read-Host 'Número de la NIC del switch privado'
(Get-Date).ToUniversalTime().ToString('o') | Set-Content (Join-Path $carpeta '00_inicio_utc.txt')
& $tshark -i $interfaz -f 'host 10.20.99.10 and host 10.20.99.20 and (tcp port 3389 or udp port 3389)' -a duration:180 -w (Join-Path $carpeta '01_rdp.pcapng')
```

Durante los 180 segundos, en CLI-RDP ejecuta `mstsc /v:10.20.99.20`. Genera **un intento fallido** con la cuenta ficticia y una contraseña incorrecta. Cierra el diálogo de error y espera al menos 20 segundos. Inicia otra conexión y autentícate con la contraseña correcta. En la sesión ejecuta `tsdiscon`, vuelve a conectar con la misma cuenta y finalmente cierra sesión. Anota la hora y el orden de cada acción sin guardar contraseñas.

## 3. Extracción

En WIN-RDP, cuando termine la captura, usa la misma consola.

```powershell
$inicio = [DateTimeOffset]::Parse((Get-Content (Join-Path $carpeta '00_inicio_utc.txt') -Raw).Trim())
$fin = $inicio.AddSeconds(180)
$filtro = @{ LogName='Security'; Id=4624,4625,4778,4779; StartTime=$inicio.LocalDateTime; EndTime=$fin.LocalDateTime }
Get-WinEvent -FilterHashtable $filtro -ErrorAction Stop |
  Sort-Object TimeCreated, RecordId |
  ForEach-Object {
    $evento = $_
    $datos = @{}
    foreach ($nodo in ([xml]$evento.ToXml()).Event.EventData.Data) {
      $datos[[string]$nodo.Name] = [string]$nodo.'#text'
    }
    $cuenta = if ($datos.TargetUserName) { $datos.TargetUserName } else { $datos.AccountName }
    $ip = if ($datos.IpAddress) { $datos.IpAddress } else { $datos.ClientAddress }
    $logon = if ($datos.TargetLogonId) { $datos.TargetLogonId } else { $datos.LogonID }
    [pscustomobject]@{
      UTC=$evento.TimeCreated.ToUniversalTime().ToString('o')
      ID=$evento.Id
      Registro=$evento.RecordId
      Host=$evento.MachineName
      Cuenta=$cuenta
      IP=$ip
      Puerto=$datos.IpPort
      Tipo=$datos.LogonType
      LogonID=$logon
      Sesion=$datos.SessionName
      Status=$datos.Status
      SubStatus=$datos.SubStatus
    }
  } | Export-Csv -LiteralPath (Join-Path $carpeta '02_eventos.csv') -NoTypeInformation -Encoding UTF8
& $tshark -r (Join-Path $carpeta '01_rdp.pcapng') -Y 'ip.src == 10.20.99.10 && ip.dst == 10.20.99.20 && tcp.dstport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -E header=y -E 'separator=,' -E quote=d -e frame.time_epoch -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport |
  Set-Content -LiteralPath (Join-Path $carpeta '03_syn_tcp.csv') -Encoding UTF8
& $tshark -r (Join-Path $carpeta '01_rdp.pcapng') -Y 'udp.port == 3389' -T fields -E header=y -E 'separator=,' -E quote=d -e frame.time_epoch -e ip.src -e udp.srcport -e ip.dst -e udp.dstport |
  Set-Content -LiteralPath (Join-Path $carpeta '04_udp.csv') -Encoding UTF8
Get-ChildItem -LiteralPath $carpeta -File | Get-FileHash -Algorithm SHA256 |
  Export-Csv -LiteralPath (Join-Path $carpeta '05_manifest_sha256.csv') -NoTypeInformation -Encoding UTF8
```

## 4. Correlación y aceptación

Deduplica los SYN por `tcp.stream` y conserva el primero de cada flujo. Convierte `frame.time_epoch` a UTC y calcula Δ = inicio de flujo − hora de evento. Filtra por host, origen y −15 ≤ Δ ≤ +5 segundos. Usa el puerto de origen si el evento lo informa y es válido. Si quedan dos candidatos, conserva ambos y marca pendiente. Si falta evidencia, registra sin asociación.

El 4624 tipo 10 confirma el inicio remoto interactivo. Un 4625 tipo 3 requiere contexto RDP y no se interpreta por sí solo. El 4778 indica reconexión y el 4779 desconexión. Úsalos para corroborar el ciclo de sesión y evitar contar dos veces eventos que también aparecen en LSM 25/24. Si faltan, registra la política y el canal disponibles. La ausencia de UDP no invalida por sí sola la conexión TCP.

## 5. Evidencias y línea base

- `06_captura_flujos.png`: filtro en Wireshark, IP de prueba, puertos y tiempos.
- `07_captura_eventos.png`: Visor de eventos filtrado y campos relevantes, sin credenciales.
- `08_correlacion.csv`: llena la plantilla anexa con UTC, IDs, candidato y veredicto.
- Para la línea base, prepara tres tareas con paquetes de evidencia equivalentes: acceso normal, alerta y ambigüedad. Define previamente una clave de corrección. Cronometra en Visor de eventos + Wireshark desde la apertura hasta el dictamen. Registra tiempos, aciertos y vínculos incorrectos. Alterna el orden de las tareas si participan varias personas. Calcula la mediana de los tiempos. Si se usan las vistas simuladas de Figma, informa la usabilidad de la interfaz por separado.

| Acción | Hora UTC | Registro y flujo | Δ segundos | Resultado |
|---|---|---|---|---|
| Fallo | Pendiente | Pendiente (Unidad III) | Pendiente | Pendiente (Unidad III) |
| Acceso | Pendiente | Pendiente (Unidad III) | Pendiente | Pendiente (Unidad III) |
| Desconexión y reconexión | Pendiente | Pendiente (Unidad III) | No aplica al vínculo de inicio | Pendiente (Unidad III) |

**Fuentes:** [Get-WinEvent](https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent) · [Auditoría de inicio de sesión](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-logon) · [Reconexión y desconexión](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-logonlogoff-events) · [TShark](https://www.wireshark.org/docs/man-pages/tshark.html).
