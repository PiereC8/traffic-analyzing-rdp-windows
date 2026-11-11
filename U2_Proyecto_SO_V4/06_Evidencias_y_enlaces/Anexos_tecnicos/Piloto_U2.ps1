# Piloto U2 - Monitor RDP en Windows
# Ejecutar EN LA MAQUINA SERVIDORA (WIN-RDP) con PowerShell como administrador.
#
# Que hace:
#   1. Verifica la politica de auditoria.
#   2. Inicia una captura de 180 s con tshark.
#   3. Espera mientras tu ejecutas las acciones RDP desde el cliente.
#   4. Extrae los eventos 4624/4625/4778/4779 de la misma ventana.
#   5. Genera acta, CSV, JSON y hash SHA-256, e imprime el resumen del piloto.
#
# Uso:
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\Piloto_U2.ps1 -Interfaz 12
#   (el numero de interfaz lo muestra antes el propio script con: tshark -D)

param(
    [int]$Interfaz = 0,
    [int]$Duracion = 180,
    [string]$Salida = "$env:USERPROFILE\U2-Piloto",
    [string]$Tshark = "$env:ProgramFiles\Wireshark\tshark.exe",
    [string]$IpCliente = "10.20.99.10"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $Salida -Force | Out-Null
$acta = Join-Path $Salida "acta_piloto.txt"

function Log($texto) {
    $linea = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $texto
    Write-Host $linea
    Add-Content -Path $acta -Value $linea
}

Log "=== PILOTO U2 · $(hostname) ==="
Log "Windows: $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# 1. Auditoria -------------------------------------------------------------
Log "--- Politica de auditoria ---"
$audit = auditpol /get /category:* | Out-String
$audit | Add-Content -Path (Join-Path $Salida "01_auditoria.txt")
$logonOK    = $audit -match "Inicio de sesión.*(Correcto|Success|Éxito)"
$procesoOK  = $audit -match "Seguimiento detallado.*(Correcto|Success|Éxito)"
Log "Inicio de sesion auditado: $logonOK"
Log "Creacion de procesos auditada: $procesoOK"
if (-not $logonOK) {
    Log "AVISO: activa 'Auditar inicio de sesion' en secpol.msc y repite."
}

# 2. Reloj -----------------------------------------------------------------
Log "--- Reloj ---"
$w32 = w32tm /query /status 2>&1 | Out-String
$w32 | Add-Content -Path (Join-Path $Salida "02_reloj.txt")
$inicioUtc = (Get-Date).ToUniversalTime()
Log ("Inicio UTC: " + $inicioUtc.ToString("o"))

# 3. Captura ---------------------------------------------------------------
if (-not (Test-Path $Tshark)) { throw "No se encontro tshark en $Tshark. Instala Wireshark con Npcap." }
if ($Interfaz -eq 0) {
    Log "Interfaces disponibles (elige una y vuelve a ejecutar con -Interfaz N):"
    & $Tshark -D
    return
}

& $Tshark -v | Out-File (Join-Path $Salida "00_version_tshark.txt") -Encoding utf8
$pcap = Join-Path $Salida "01_rdp.pcapng"
$filtro = "host $IpCliente and (tcp port 3389 or udp port 3389)"
Log "--- Captura: $Duracion s en interfaz $Interfaz ---"
Log "Filtro: $filtro"
Log "AHORA, desde el cliente: fallo, espera 20 s, acceso correcto, tsdiscon, reconexion y cierre."

$proc = Start-Process -FilePath $Tshark -ArgumentList @(
    "-i", $Interfaz, "-f", $filtro, "-a", "duration:$Duracion", "-w", $pcap
) -PassThru -WindowStyle Hidden

$finUtc = $inicioUtc.AddSeconds($Duracion)
for ($t = $Duracion; $t -gt 0; $t -= 15) {
    Log ("Faltan {0} s (fin a las {1} UTC)" -f $t, $finUtc.ToString("HH:mm:ss"))
    Start-Sleep -Seconds 15
}
$proc.WaitForExit(30000) | Out-Null
if (-not $proc.HasExited) { $proc.Kill() }
Log "Captura terminada."

# 4. Eventos ---------------------------------------------------------------
Log "--- Extraccion de eventos ---"
$filtroEv = @{
    LogName   = 'Security'
    Id        = 4624, 4625, 4778, 4779
    StartTime = $inicioUtc.ToLocalTime()
    EndTime   = $inicioUtc.AddSeconds($Duracion + 30).ToLocalTime()
}
$eventos = Get-WinEvent -FilterHashtable $filtroEv -ErrorAction SilentlyContinue
$filas = @()
foreach ($e in $eventos) {
    $datos = @{}
    foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $datos[[string]$n.Name] = [string]$n.'#text' }
    $filas += [pscustomobject]@{
        Hora     = $e.TimeCreated.ToUniversalTime().ToString("o")
        Id       = $e.Id
        Cuenta   = if ($datos.TargetUserName) { $datos.TargetUserName } else { $datos.SubjectUserName }
        Tipo     = $datos.LogonType
        IpOrigen = $datos.IpAddress
        LogonId  = if ($datos.TargetLogonId) { $datos.TargetLogonId } else { $datos.LogonId }
        SessionId= $datos.SessionName
    }
}
$csv = Join-Path $Salida "03_eventos.csv"
$filas | Sort-Object Hora | Export-Csv -Path $csv -NoTypeInformation -Encoding utf8

$n4624 = ($filas | Where-Object { $_.Id -eq 4624 -and $_.Tipo -eq 10 }).Count
$n4625 = ($filas | Where-Object { $_.Id -eq 4625 }).Count
$n4778 = ($filas | Where-Object { $_.Id -eq 4778 }).Count
$n4779 = ($filas | Where-Object { $_.Id -eq 4779 }).Count
Log "4624 tipo 10: $n4624 | 4625: $n4625 | 4778: $n4778 | 4779: $n4779"

# 5. Flujos ----------------------------------------------------------------
$flujos = 0
if (Test-Path $pcap) {
    $campos = & $Tshark -r $pcap -Y "tcp.port == 3389 or udp.port == 3389" -T fields `
        -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.syn 2>$null
    $flujos = ($campos | Where-Object { $_ -match '\S' }).Count
    $campos | Out-File (Join-Path $Salida "04_flujos_3389.txt") -Encoding utf8
}
Log "Paquetes en 3389: $flujos"

# 6. Manifiesto y resumen --------------------------------------------------
$archivos = Get-ChildItem $Salida -File | Where-Object { $_.Name -ne "05_manifiesto.txt" }
$manifiesto = foreach ($a in $archivos) {
    $h = (Get-FileHash $a.FullName -Algorithm SHA256).Hash
    "$h  $($a.Name)"
}
$manifiesto | Out-File (Join-Path $Salida "05_manifiesto.txt") -Encoding utf8
Log "Manifiesto SHA-256 generado con $($archivos.Count) archivos."

$resumen = [pscustomobject]@{
    Equipo            = hostname
    InicioUtc         = $inicioUtc.ToString("o")
    DuracionSegundos  = $Duracion
    Eventos4624_tipo10= $n4624
    Eventos4625       = $n4625
    Eventos4778       = $n4778
    Eventos4779       = $n4779
    Paquetes3389      = $flujos
    Cumple4624        = ($n4624 -ge 1)
    Cumple4625        = ($n4625 -ge 1)
    CumpleFlujos      = ($flujos -ge 1)
}
$resumen | ConvertTo-Json | Out-File (Join-Path $Salida "06_resumen.json") -Encoding utf8

Log "=== RESUMEN DEL PILOTO ==="
$resumen | Format-List | Out-String | ForEach-Object { Write-Host $_; Add-Content -Path $acta -Value $_ }
Log "Carpeta: $Salida"
Log "Envia el contenido de esta carpeta (o el resumen y el acta) para incorporarlo al informe."
