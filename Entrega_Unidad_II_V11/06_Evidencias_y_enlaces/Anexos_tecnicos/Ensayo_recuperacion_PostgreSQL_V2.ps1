# Ensayo preliminar de recuperacion de PostgreSQL (mide el RTO de CP-07)
# Crea una base de prueba con 30 000 eventos (unos 30 MiB de datos en bruto; la copia comprimida pesa menos), hace la copia
# con pg_dump (formato custom), la restaura en una base nueva y compara el contenido.
# Uso (PowerShell, sin permisos de administrador):  .\Ensayo_recuperacion_PostgreSQL_V1.ps1
# Requisito: PostgreSQL 16 instalado (su carpeta bin se busca en "C:\Program Files\PostgreSQL").
# Salida: Anexo_V_Resultado_ensayo_recuperacion.csv junto a este archivo.

$ErrorActionPreference = 'Stop'
$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
$raiz = 'C:\Program Files\PostgreSQL'
$bin = Get-ChildItem $raiz -Directory | Sort-Object { [int]($_.Name -replace '\D','0') } -Descending | Select-Object -First 1
if (-not $bin) { throw "No se encontro PostgreSQL en $raiz" }
$bin = Join-Path $bin.FullName 'bin'
$psql = Join-Path $bin 'psql.exe'; $pgdump = Join-Path $bin 'pg_dump.exe'; $pgrestore = Join-Path $bin 'pg_restore.exe'
Write-Host "Usando $bin"

$seg = Read-Host 'Contrasena del usuario postgres' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($seg)
$env:PGPASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
$env:PGUSER = 'postgres'; $env:PGHOST = 'localhost'; $env:PGPORT = '5432'

function Sql($db, $cmd) { (& $psql -d $db -t -A -v ON_ERROR_STOP=1 -c $cmd) -join '' }

$origen = 'lab_rto'; $destino = 'lab_rto_restore'
$dump = Join-Path $env:TEMP 'lab_rto.dump'
foreach ($b in @($origen, $destino)) { Sql 'postgres' "DROP DATABASE IF EXISTS $b" | Out-Null }

# 1. Base de prueba
Sql 'postgres' "CREATE DATABASE $origen" | Out-Null
Sql $origen "CREATE TABLE evidence (evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), host text, ts timestamptz, event_id int, payload text)" | Out-Null
Sql $origen "INSERT INTO evidence(host, ts, event_id, payload) SELECT 'WIN-RDP', now() - (g || ' seconds')::interval, (ARRAY[4624,4625,4779,21,24,25])[1 + g % 6], repeat(md5(g::text), 32) FROM generate_series(1,30000) g" | Out-Null
Sql $origen "CREATE INDEX ON evidence(ts)" | Out-Null
$resumen = "SELECT count(*) || '|' || md5(string_agg(evidence_id::text || ':' || host || ':' || ts::text || ':' || event_id::text || ':' || md5(payload), ',' ORDER BY evidence_id)) FROM evidence"
$antes = Sql $origen $resumen
Write-Host "Origen: $antes"

# 2. Copia (RPO: datos hasta este momento)
$t1 = [Diagnostics.Stopwatch]::StartNew()
& $pgdump -Fc -f $dump $origen
if ($LASTEXITCODE -ne 0) { throw 'pg_dump fallo' }
$t1.Stop()
$hash = (Get-FileHash $dump -Algorithm SHA256).Hash
$mb = [math]::Round((Get-Item $dump).Length / 1MB, 2)
Write-Host "Copia: $mb MB en $([math]::Round($t1.Elapsed.TotalSeconds,2)) s; SHA-256 $hash"

# 3. Restauracion y verificacion (esto es el RTO medido)
$t2 = [Diagnostics.Stopwatch]::StartNew()
Sql 'postgres' "CREATE DATABASE $destino" | Out-Null
& $pgrestore -d $destino $dump
if ($LASTEXITCODE -ne 0) { throw 'pg_restore fallo' }
$despues = Sql $destino $resumen
$t2.Stop()
$ok = if ($antes -eq $despues) { 'coincide' } else { 'NO COINCIDE' }
Write-Host "Restauracion: $([math]::Round($t2.Elapsed.TotalSeconds,2)) s; contenido $ok ($despues)"

# 4. Registro
$fila = [pscustomobject]@{
    Fecha = (Get-Date -Format 'yyyy-MM-dd HH:mm')
    Equipo = $env:COMPUTERNAME
    Filas = ($antes -split '\|')[0]
    Tamano_copia_MB = $mb
    SHA256_copia = $hash
    Segundos_copia = [math]::Round($t1.Elapsed.TotalSeconds, 2)
    Segundos_restauracion_y_verificacion = [math]::Round($t2.Elapsed.TotalSeconds, 2)
    Contenido = $ok
    Nota = 'SHA-256 corresponde a esta copia; varia entre ejecuciones'
}
$salida = Join-Path $aqui 'Anexo_V_Resultado_ensayo_recuperacion.csv'
$fila | Export-Csv $salida -Delimiter ';' -NoTypeInformation -Encoding UTF8
Write-Host "Guardado: $salida"

# 5. Limpieza (opcional)
$r = Read-Host 'Borrar las bases de prueba y la copia? (s/n)'
if ($r -eq 's') { foreach ($b in @($origen, $destino)) { Sql 'postgres' "DROP DATABASE IF EXISTS $b" | Out-Null }; Remove-Item $dump }
Remove-Item Env:PGPASSWORD
