#Requires -Version 5.1

<#
.SYNOPSIS
    Sistema Completo de Diagnóstico e Manutenção - Versão 4.0 ULTRA DEFINITIVA
.DESCRIPTION
    Menu interativo, manutenção automática, diagnóstico completo e relatórios HTML profissionais
.NOTES
    Versão: 4.0 Ultra Definitiva
    Desenvolvido por: Wilton Lima
    GitHub: github.com/willimaofc
    LinkedIn: linkedin.com/in/wil-limaofc
#>

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$OutputPath = "$env:USERPROFILE\Desktop\Diagnostico_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$BatteryReportPath = "$env:TEMP\battery-report.html"
$MaintenanceLog = @()
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Get-SafeData {
    param([string]$Description, [scriptblock]$ScriptBlock, [object]$DefaultValue = $null)
    try {
        $result = & $ScriptBlock
        if ($null -eq $result -or ($result -is [array] -and $result.Count -eq 0)) { return $DefaultValue }
        return $result
    } catch {
        Write-Warning "Erro: $Description"
        return $DefaultValue
    }
}

function Format-SafeValue {
    param($Value, $Default = "N/A")
    if ($null -eq $Value -or $Value -eq "" -or $Value -eq 0) { return $Default }
    return $Value
}

function Clear-TempFiles {
    param([bool]$DeepClean = $false)
    
    $freedSpace = 0
    $script:MaintenanceLog += "=== Limpeza de Temporários ==="
    
    try {
        # Temp do usuário
        $tempPath = $env:TEMP
        if (Test-Path $tempPath) {
            try {
                $before = (Get-ChildItem $tempPath -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                if ($null -eq $before) { $before = 0 }
                
                Get-ChildItem $tempPath -Recurse -Force -EA SilentlyContinue | ForEach-Object {
                    try {
                        Remove-Item $_.FullName -Force -Recurse -EA SilentlyContinue
                    } catch { }
                }
                
                $after = (Get-ChildItem $tempPath -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                if ($null -eq $after) { $after = 0 }
                
                $freed = if ($before -gt 0) { [math]::Round(($before - $after) / 1MB, 2) } else { 0 }
                $freedSpace += $freed
                $script:MaintenanceLog += "✓ Temp usuário: $freed MB"
            } catch {
                $script:MaintenanceLog += "⚠ Temp usuário: erro parcial"
            }
        }
        
        # Windows Temp (só admin)
        if ($IsAdmin) {
            $winTemp = "C:\Windows\Temp"
            if (Test-Path $winTemp) {
                try {
                    $before = (Get-ChildItem $winTemp -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $before) { $before = 0 }
                    
                    Get-ChildItem $winTemp -Recurse -Force -EA SilentlyContinue | ForEach-Object {
                        try {
                            Remove-Item $_.FullName -Force -Recurse -EA SilentlyContinue
                        } catch { }
                    }
                    
                    $after = (Get-ChildItem $winTemp -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $after) { $after = 0 }
                    
                    $freed = if ($before -gt 0) { [math]::Round(($before - $after) / 1MB, 2) } else { 0 }
                    $freedSpace += $freed
                    $script:MaintenanceLog += "✓ Windows Temp: $freed MB"
                } catch {
                    $script:MaintenanceLog += "⚠ Windows Temp: erro parcial"
                }
            }
        }
        
        # Prefetch (deep clean + admin)
        if ($IsAdmin -and $DeepClean) {
            $prefetch = "C:\Windows\Prefetch"
            if (Test-Path $prefetch) {
                try {
                    $before = (Get-ChildItem $prefetch -Filter "*.pf" -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $before) { $before = 0 }
                    
                    Get-ChildItem $prefetch -Filter "*.pf" -EA SilentlyContinue | ForEach-Object {
                        try {
                            Remove-Item $_.FullName -Force -EA SilentlyContinue
                        } catch { }
                    }
                    
                    $after = (Get-ChildItem $prefetch -Filter "*.pf" -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $after) { $after = 0 }
                    
                    $freed = if ($before -gt 0) { [math]::Round(($before - $after) / 1MB, 2) } else { 0 }
                    $freedSpace += $freed
                    $script:MaintenanceLog += "✓ Prefetch: $freed MB"
                } catch {
                    $script:MaintenanceLog += "⚠ Prefetch: erro"
                }
            }
        }
        
        # Cache de navegadores (deep clean)
        if ($DeepClean) {
            # Chrome
            $chromeCache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
            if (Test-Path $chromeCache) {
                try {
                    $before = (Get-ChildItem $chromeCache -Recurse -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $before) { $before = 0 }
                    
                    Get-ChildItem $chromeCache -Recurse -EA SilentlyContinue | Remove-Item -Force -Recurse -EA SilentlyContinue
                    
                    $after = (Get-ChildItem $chromeCache -Recurse -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $after) { $after = 0 }
                    
                    $freed = if ($before -gt 0) { [math]::Round(($before - $after) / 1MB, 2) } else { 0 }
                    $freedSpace += $freed
                    $script:MaintenanceLog += "✓ Chrome Cache: $freed MB"
                } catch {
                    $script:MaintenanceLog += "⚠ Chrome Cache: não acessível"
                }
            }
            
            # Edge
            $edgeCache = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
            if (Test-Path $edgeCache) {
                try {
                    $before = (Get-ChildItem $edgeCache -Recurse -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $before) { $before = 0 }
                    
                    Get-ChildItem $edgeCache -Recurse -EA SilentlyContinue | Remove-Item -Force -Recurse -EA SilentlyContinue
                    
                    $after = (Get-ChildItem $edgeCache -Recurse -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum
                    if ($null -eq $after) { $after = 0 }
                    
                    $freed = if ($before -gt 0) { [math]::Round(($before - $after) / 1MB, 2) } else { 0 }
                    $freedSpace += $freed
                    $script:MaintenanceLog += "✓ Edge Cache: $freed MB"
                } catch {
                    $script:MaintenanceLog += "⚠ Edge Cache: não acessível"
                }
            }
        }
        
        $script:MaintenanceLog += "=== Total Liberado: $freedSpace MB ==="
        return $freedSpace
        
    } catch {
        $script:MaintenanceLog += "✗ Erro geral: $($_.Exception.Message)"
        return $freedSpace
    }
}

function Clear-RecycleBin {
    try {
        $script:MaintenanceLog += "=== Lixeira ==="
        
        # Método 1: PowerShell nativo
        try {
            Clear-RecycleBin -Force -EA Stop
            $script:MaintenanceLog += "✓ Lixeira esvaziada"
            return $true
        } catch {
            # Método 2: Shell COM
            try {
                $shell = New-Object -ComObject Shell.Application
                $recycleBin = $shell.Namespace(0xA)
                $recycleBin.Items() | ForEach-Object { Remove-Item $_.Path -Force -Recurse -EA SilentlyContinue }
                $script:MaintenanceLog += "✓ Lixeira esvaziada (método alternativo)"
                return $true
            } catch {
                $script:MaintenanceLog += "⚠ Lixeira: não foi possível esvaziar"
                return $false
            }
        }
    } catch {
        $script:MaintenanceLog += "✗ Erro lixeira: $($_.Exception.Message)"
        return $false
    }
}

function Clear-DNSCache {
    try {
        $script:MaintenanceLog += "=== DNS Cache ==="
        
        # Método 1: Clear-DnsClientCache
        try {
            Clear-DnsClientCache -EA Stop
            $script:MaintenanceLog += "✓ DNS Cache limpo"
            return $true
        } catch {
            # Método 2: ipconfig /flushdns
            try {
                $result = & ipconfig /flushdns 2>&1
                if ($result -match "Successfully|êxito") {
                    $script:MaintenanceLog += "✓ DNS Cache limpo (ipconfig)"
                    return $true
                } else {
                    $script:MaintenanceLog += "⚠ DNS Cache: comando executado mas status incerto"
                    return $true
                }
            } catch {
                $script:MaintenanceLog += "✗ DNS Cache: falhou"
                return $false
            }
        }
    } catch {
        $script:MaintenanceLog += "✗ Erro DNS: $($_.Exception.Message)"
        return $false
    }
}

# BANNER
Clear-Host
Write-Host ""
Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  DIAGNÓSTICO E MANUTENÇÃO v4.0 ULTRA          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Desenvolvido por: " -NoNewline -ForegroundColor White
Write-Host "Wilton Lima" -ForegroundColor White
Write-Host "  GitHub: github.com/willimaofc" -ForegroundColor White
Write-Host "  LinkedIn: linkedin.com/in/wil-limaofc" -ForegroundColor White
Write-Host ""
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if (-not $IsAdmin) {
    Write-Host "⚠️  AVISO: Modo Usuário (funcionalidades limitadas)" -ForegroundColor Yellow
    Write-Host ""
}

# MENU
Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║  [1] 📊 Diagnóstico Completo                  ║" -ForegroundColor White
Write-Host "║  [2] 🧹 Diagnóstico + Limpeza Rápida          ║" -ForegroundColor White
Write-Host "║  [3] 🚀 Diagnóstico + Limpeza Profunda        ║" -ForegroundColor White
Write-Host "║  [4] ⚡ Otimização Completa                    ║" -ForegroundColor White
Write-Host "║  [0] ❌ Sair                                   ║" -ForegroundColor White
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Digite [0-4]"

switch ($choice) {
    "0" { Write-Host "Saindo... 👋" -ForegroundColor Cyan; exit }
    "1" { $Mode = "Diagnóstico"; $DoMaintenance = $false; $DeepClean = $false }
    "2" { 
        if (-not $IsAdmin) { Write-Host "❌ Requer Admin!" -ForegroundColor Red; Read-Host; exit }
        $Mode = "Limpeza Rápida"; $DoMaintenance = $true; $DeepClean = $false 
    }
    "3" { 
        if (-not $IsAdmin) { Write-Host "❌ Requer Admin!" -ForegroundColor Red; Read-Host; exit }
        $Mode = "Limpeza Profunda"; $DoMaintenance = $true; $DeepClean = $true 
    }
    "4" { 
        if (-not $IsAdmin) { Write-Host "❌ Requer Admin!" -ForegroundColor Red; Read-Host; exit }
        $Mode = "Otimização Completa"; $DoMaintenance = $true; $DeepClean = $true
        Write-Host "⚠️  Pode demorar 15-30 minutos!" -ForegroundColor Yellow
        if ((Read-Host "Continuar? (S/N)") -ne "S") { exit }
    }
    default { Write-Host "❌ Opção inválida!" -ForegroundColor Red; exit }
}

Write-Host ""
Write-Host "✓ Modo: $Mode" -ForegroundColor Green
Write-Host ""

$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

# MANUTENÇÃO
if ($DoMaintenance) {
    Write-Host "🔧 Manutenção..." -ForegroundColor Cyan
    Write-Host "[1/5] Temporários..." -ForegroundColor Yellow
    $freedSpace = Clear-TempFiles -DeepClean $DeepClean
    Write-Host "✓ $freedSpace MB liberados" -ForegroundColor Green
    
    Write-Host "[2/5] Lixeira..." -ForegroundColor Yellow
    Clear-RecycleBin
    Write-Host "✓ OK" -ForegroundColor Green
    
    Write-Host "[3/5] DNS..." -ForegroundColor Yellow
    Clear-DNSCache
    Write-Host "✓ OK" -ForegroundColor Green
    
    if ($DeepClean) {
        Write-Host "[4/5] Windows Update..." -ForegroundColor Yellow
        try {
            Stop-Service wuauserv -Force -EA SilentlyContinue
            Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -EA SilentlyContinue
            Start-Service wuauserv -EA SilentlyContinue
            $script:MaintenanceLog += "✓ WU Cache limpo"
            Write-Host "✓ OK" -ForegroundColor Green
        } catch {
            $script:MaintenanceLog += "✗ Erro WU"
            Write-Host "⚠ Erro" -ForegroundColor Yellow
        }
    }
    
    Write-Host "[5/5] Otimização disco..." -ForegroundColor Yellow
    try {
        Optimize-Volume -DriveLetter C -ReTrim -EA SilentlyContinue
        $script:MaintenanceLog += "✓ Otimização OK"
        Write-Host "✓ OK" -ForegroundColor Green
    } catch {
        Write-Host "⚠ N/A" -ForegroundColor Yellow
    }
    Write-Host ""
}

# COLETA
Write-Host "📊 Coletando dados..." -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/21] Sistema..." -ForegroundColor Yellow
$ComputerInfo = Get-SafeData "ComputerInfo" { Get-ComputerInfo } @{}
$OSInfo = Get-SafeData "OSInfo" { Get-CimInstance Win32_OperatingSystem } @{}
$BIOS = Get-SafeData "BIOS" { Get-CimInstance Win32_BIOS } @{}
$SystemEnclosure = Get-SafeData "SystemEnclosure" { Get-CimInstance Win32_SystemEnclosure } @{}

Write-Host "[2/21] Hardware..." -ForegroundColor Yellow
$CPU = Get-SafeData "CPU" { Get-CimInstance Win32_Processor } @{}
$RAM = Get-SafeData "RAM" { Get-CimInstance Win32_PhysicalMemory } @()
$Motherboard = Get-SafeData "Motherboard" { Get-CimInstance Win32_BaseBoard } @{}

Write-Host "[3/21] Armazenamento..." -ForegroundColor Yellow
$Disks = Get-SafeData "Disks" { Get-CimInstance Win32_DiskDrive } @()
$Volumes = Get-SafeData "Volumes" { Get-Volume | Where-Object {$_.DriveLetter} } @()
$PhysicalDisks = Get-SafeData "PhysicalDisks" { Get-PhysicalDisk } @()
$PartitionInfo = Get-SafeData "PartitionInfo" { Get-Partition } @()

Write-Host "[4/21] Rede..." -ForegroundColor Yellow
$NetworkAdapters = Get-SafeData "NetworkAdapters" { Get-NetAdapter | Where-Object {$_.Status -eq "Up"} } @()
$IPConfig = Get-SafeData "IPConfig" { Get-NetIPConfiguration } @()

Write-Host "[5/21] Vídeo..." -ForegroundColor Yellow
$GPU = Get-SafeData "GPU" { Get-CimInstance Win32_VideoController } @()

Write-Host "[6/21] Som..." -ForegroundColor Yellow
$SoundDevices = Get-SafeData "SoundDevices" { Get-CimInstance Win32_SoundDevice } @()

Write-Host "[7/21] Software..." -ForegroundColor Yellow
$InstalledSoftware = Get-SafeData "InstalledSoftware" {
    $soft = @()
    $soft += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -EA SilentlyContinue
    $soft += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -EA SilentlyContinue
    $soft | Where-Object {$_.DisplayName} | Select DisplayName, DisplayVersion, Publisher, InstallDate | Sort DisplayName -Unique
} @()

Write-Host "[8/21] Serviços..." -ForegroundColor Yellow
$Services = Get-SafeData "Services" { Get-Service | Sort Status, DisplayName } @()

Write-Host "[9/21] Processos..." -ForegroundColor Yellow
$Processes = Get-SafeData "Processes" { Get-Process | Sort CPU -Descending | Select -First 30 } @()

Write-Host "[10/21] Drivers..." -ForegroundColor Yellow
$Drivers = Get-SafeData "Drivers" { if ($IsAdmin) { Get-WindowsDriver -Online | Select -First 50 } else { @() } } @()

Write-Host "[11/21] Atualizações..." -ForegroundColor Yellow
$Updates = Get-SafeData "Updates" { Get-HotFix | Sort InstalledOn -Descending | Select -First 30 } @()

Write-Host "[12/21] Bateria + Report..." -ForegroundColor Yellow
$Battery = Get-SafeData "Battery" { Get-CimInstance Win32_Battery -EA SilentlyContinue } $null
$BatteryReportGenerated = $false
$BatteryReportHTML = ""

if ($Battery) {
    try {
        powercfg /batteryreport /output $BatteryReportPath 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        if (Test-Path $BatteryReportPath) {
            $BatteryReportHTML = Get-Content $BatteryReportPath -Raw -EA SilentlyContinue
            $BatteryReportGenerated = $true
            Write-Host "   ✓ Battery Report OK" -ForegroundColor Green
        }
    } catch { }
}

$BatteryStatus = Get-SafeData "BatteryStatus" { 
    if ($IsAdmin -and $Battery) { Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -EA SilentlyContinue } else { $null }
} $null

$BatteryStaticData = Get-SafeData "BatteryStaticData" {
    if ($IsAdmin -and $Battery) { Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -EA SilentlyContinue } else { $null }
} $null

$BatteryCycleCount = Get-SafeData "BatteryCycleCount" {
    if ($IsAdmin -and $Battery) { Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount -EA SilentlyContinue } else { $null }
} $null

Write-Host "[13/21] Impressoras..." -ForegroundColor Yellow
$Printers = Get-SafeData "Printers" { Get-Printer } @()

Write-Host "[14/21] Variáveis..." -ForegroundColor Yellow
$EnvVariables = Get-SafeData "EnvVariables" { Get-ChildItem Env: | Sort Name } @()

Write-Host "[15/21] Logs..." -ForegroundColor Yellow
$SystemErrors = Get-SafeData "SystemErrors" { 
    if ($IsAdmin) { Get-EventLog -LogName System -EntryType Error -Newest 15 -EA SilentlyContinue }
    else { Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 15 -EA SilentlyContinue }
} @()

$ApplicationErrors = Get-SafeData "ApplicationErrors" { 
    if ($IsAdmin) { Get-EventLog -LogName Application -EntryType Error -Newest 15 -EA SilentlyContinue }
    else { Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 15 -EA SilentlyContinue }
} @()

Write-Host "[16/21] Firewall..." -ForegroundColor Yellow
$FirewallProfile = Get-SafeData "FirewallProfile" { Get-NetFirewallProfile } @()

Write-Host "[17/21] USB..." -ForegroundColor Yellow
$USBDevices = Get-SafeData "USBDevices" { Get-PnpDevice -Class USB | Where-Object {$_.Status -eq "OK"} } @()

Write-Host "[18/21] Conectividade..." -ForegroundColor Yellow
$PingGoogle = Get-SafeData "PingGoogle" { 
    $result = Test-Connection -ComputerName 8.8.8.8 -Count 2 -ErrorAction SilentlyContinue
    if ($result) { $true } else { $false }
} $false

$PingDNS = Get-SafeData "PingDNS" { 
    $result = Test-Connection -ComputerName dns.google -Count 2 -ErrorAction SilentlyContinue
    if ($result) { $true } else { $false }
} $false

$InternetSpeed = Get-SafeData "InternetSpeed" {
    try {
        Write-Host "   Testando velocidade..." -ForegroundColor Gray
        $TestFile = "http://speedtest.ftp.otenet.gr/files/test10Mb.db"
        $Start = Get-Date
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadData($TestFile) | Out-Null
        $WebClient.Dispose()
        $Time = ((Get-Date) - $Start).TotalSeconds
        if ($Time -gt 0) {
            $Speed = [math]::Round((10 / $Time) * 8, 2)
            Write-Host "   ✓ $Speed Mbps" -ForegroundColor Green
            $Speed
        } else { 0 }
    } catch { 
        Write-Host "   ⚠ Não foi possível testar" -ForegroundColor Yellow
        0 
    }
} 0

Write-Host "[19/21] Temperatura..." -ForegroundColor Yellow
$Temperature = Get-SafeData "Temperature" {
    $temp = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -EA SilentlyContinue
    if ($temp -and $temp.CurrentTemperature) {
        if ($temp -is [array]) {
            $avgTemp = ($temp | Measure-Object -Property CurrentTemperature -Average).Average
            [math]::Round(($avgTemp / 10) - 273.15, 1)
        } else {
            [math]::Round(($temp.CurrentTemperature / 10) - 273.15, 1)
        }
    } else { $null }
} $null

Write-Host "[20/21] Drivers desatualizados..." -ForegroundColor Yellow
$OutdatedDrivers = Get-SafeData "OutdatedDrivers" {
    if ($IsAdmin) {
        $AllDrivers = Get-WindowsDriver -Online | Select -First 100
        $AllDrivers | Where-Object { $_.Date -lt (Get-Date).AddYears(-2) } | Select -First 20
    } else { @() }
} @()

Write-Host "[21/21] Startup..." -ForegroundColor Yellow
$StartupPrograms = Get-SafeData "StartupPrograms" {
    Get-CimInstance Win32_StartupCommand | Select Name, Command, Location, User
} @()

# Cálculos
$TotalRAM = if ($ComputerInfo.CsTotalPhysicalMemory) { $ComputerInfo.CsTotalPhysicalMemory } else { 0 }
$FreeRAM = if ($OSInfo.FreePhysicalMemory) { $OSInfo.FreePhysicalMemory * 1KB } else { 0 }
$UsedRAM = if ($TotalRAM -gt 0 -and $FreeRAM -gt 0) { $TotalRAM - $FreeRAM } else { 0 }
$RAMUsedPercent = if ($TotalRAM -gt 0) { [math]::Round(($UsedRAM / $TotalRAM) * 100, 1) } else { 0 }
$RAMFreePercent = if ($TotalRAM -gt 0) { [math]::Round(($FreeRAM / $TotalRAM) * 100, 1) } else { 0 }

Write-Host ""
Write-Host "✓ Coleta concluída!" -ForegroundColor Green
Write-Host ""

Write-Host "📝 Gerando HTML..." -ForegroundColor Green
Write-Host ""

$HTML = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnóstico do Sistema - $(Get-Date -Format 'dd/MM/yyyy HH:mm')</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        header { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); color: white; padding: 40px; text-align: center; position: relative; }
        header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        header p { font-size: 1.1em; opacity: 0.9; }
        .admin-badge { position: absolute; top: 20px; right: 20px; padding: 8px 15px; background: #27ae60; color: white; border-radius: 20px; font-size: 0.9em; font-weight: bold; }
        .warning-badge { background: #f39c12; }
        .mode-badge { position: absolute; top: 60px; right: 20px; padding: 8px 15px; background: rgba(255,255,255,0.2); color: white; border-radius: 20px; font-size: 0.85em; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; padding: 20px; background: #f8f9fa; scroll-margin-top: 20px; }
        .info-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); transition: transform 0.3s, box-shadow 0.3s; }
        .info-card:hover { transform: translateY(-5px); box-shadow: 0 5px 20px rgba(0,0,0,0.2); }
        .info-card h3 { color: #667eea; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #667eea; font-size: 1.3em; }
        .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        .info-row:last-child { border-bottom: none; }
        .info-label { font-weight: 600; color: #555; }
        .info-value { color: #777; text-align: right; max-width: 60%; word-break: break-word; }
        .section { padding: 30px; scroll-margin-top: 20px; }
        .section h2 { color: #2c3e50; margin-bottom: 20px; font-size: 1.8em; border-left: 5px solid #667eea; padding-left: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        thead { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        th { padding: 15px; text-align: left; font-weight: 600; text-transform: uppercase; font-size: 0.9em; letter-spacing: 0.5px; }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        tr:last-child td { border-bottom: none; }
        .status-ok { color: #27ae60; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-error { color: #e74c3c; font-weight: bold; }
        .progress-bar { width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; margin-top: 5px; }
        .progress-fill { height: 100%; transition: width 0.3s; }
        .progress-normal { background: linear-gradient(90deg, #27ae60 0%, #2ecc71 100%); }
        .progress-warning { background: linear-gradient(90deg, #f39c12 0%, #f1c40f 100%); }
        .progress-danger { background: linear-gradient(90deg, #e74c3c 0%, #c0392b 100%); }
        footer { background: #2c3e50; color: white; padding: 30px 20px; text-align: center; }
        footer a { transition: all 0.3s ease; color: white; text-decoration: none; }
        footer a:hover { background: rgba(255,255,255,0.3) !important; transform: translateY(-2px); }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 5px; font-size: 0.85em; font-weight: 600; }
        .badge-success { background: #27ae60; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-info { background: #3498db; color: white; }
        .no-data { text-align: center; padding: 20px; color: #95a5a6; font-style: italic; }
        a[href^="#"]:hover { transform: translateX(5px); box-shadow: 0 4px 12px rgba(0,0,0,0.15) !important; }
        html { scroll-behavior: smooth; }
        .back-to-top { position: fixed; bottom: 30px; right: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; width: 50px; height: 50px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 4px 15px rgba(0,0,0,0.3); transition: all 0.3s ease; text-decoration: none; font-size: 1.5em; }
        .back-to-top:hover { transform: translateY(-5px); box-shadow: 0 6px 20px rgba(0,0,0,0.4); }
        .maintenance-log { background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 10px; font-family: 'Courier New', monospace; font-size: 0.9em; line-height: 1.6; max-height: 400px; overflow-y: auto; }
        .maintenance-log .success { color: #2ecc71; }
        .maintenance-log .error { color: #e74c3c; }
        .maintenance-log .title { color: #3498db; font-weight: bold; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } .back-to-top { display: none; } }
        @media (max-width: 768px) { .info-grid { grid-template-columns: 1fr; } header h1 { font-size: 1.8em; } .admin-badge, .mode-badge { position: static; display: inline-block; margin-top: 10px; } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="admin-badge $(if(-not $IsAdmin){'warning-badge'})">
                $(if($IsAdmin){'✓ Administrador'}else{'⚠ Usuário'})
            </div>
            <div class="mode-badge">🔧 $Mode</div>
            <h1>🖥️ Diagnóstico e Manutenção</h1>
            <p>Gerado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
            <p>Computador: $(Format-SafeValue $ComputerInfo.CsName)</p>
            <p style="margin-top: 10px; opacity: 0.8;">v4.0 Ultra Definitiva</p>
        </header>

        <!-- SUMÁRIO -->
        <div style="background: #f8f9fa; padding: 30px; border-bottom: 3px solid #667eea;">
            <h2 style="color: #2c3e50; margin-bottom: 20px; text-align: center;">📑 Sumário</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; max-width: 1200px; margin: 0 auto;">
"@

# Links do sumário
$summaryItems = @(
    @{Icon="💻"; Title="Info Geral"; Link="info-geral"; Color="#667eea"}
    @{Icon="💾"; Title="RAM"; Link="ram-details"; Color="#11998e"}
    @{Icon="💿"; Title="Disco C:"; Link="disco-c"; Color="#764ba2"}
    @{Icon="🗄️"; Title="Armazenamento"; Link="armazenamento"; Color="#e74c3c"}
    @{Icon="📦"; Title="Software"; Link="software"; Color="#3498db"}
    @{Icon="⚙️"; Title="Processos"; Link="processos"; Color="#f39c12"}
    @{Icon="🔄"; Title="Serviços"; Link="servicos"; Color="#9b59b6"}
    @{Icon="🔄"; Title="Atualizações"; Link="atualizacoes"; Color="#16a085"}
    @{Icon="🌐"; Title="Conectividade"; Link="conectividade"; Color="#27ae60"}
    @{Icon="🌡️"; Title="Temperatura"; Link="temperatura"; Color="#e67e22"}
    @{Icon="🛡️"; Title="Firewall"; Link="firewall"; Color="#c0392b"}
    @{Icon="⚠️"; Title="Eventos"; Link="eventos"; Color="#d35400"}
    @{Icon="🔧"; Title="Drivers"; Link="drivers"; Color="#8e44ad"}
    @{Icon="🔌"; Title="USB"; Link="usb"; Color="#2980b9"}
    @{Icon="🔋"; Title="Bateria"; Link="bateria"; Color="#f1c40f"}
)

if ($DoMaintenance) {
    $summaryItems += @{Icon="🧹"; Title="Log Manutenção"; Link="manutencao"; Color="#e67e22"}
}

$summaryItems += @{Icon="📊"; Title="Resumo"; Link="resumo"; Color="#34495e"}

foreach ($item in $summaryItems) {
    $HTML += @"
                <a href="#$($item.Link)" style="text-decoration: none; padding: 12px 20px; background: white; border-left: 4px solid $($item.Color); border-radius: 5px; color: #2c3e50; transition: all 0.3s; display: flex; align-items: center; gap: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                    <span style="font-size: 1.5em;">$($item.Icon)</span>
                    <span><strong>$($item.Title)</strong></span>
                </a>
"@
}

$HTML += @"
            </div>
            <div style="text-align: center; margin-top: 20px; padding: 15px; background: rgba(102, 126, 234, 0.1); border-radius: 5px;">
                <p style="margin: 0; color: #555;">💡 <strong>Dica:</strong> Clique para navegar</p>
            </div>
        </div>
"@

# LOG DE MANUTENÇÃO
if ($DoMaintenance -and $MaintenanceLog.Count -gt 0) {
    $HTML += @"
        <div class="section" id="manutencao">
            <h2>🧹 Log de Manutenção</h2>
            <div class="maintenance-log">
                <div class="title">═══════════════════════════════════════</div>
                <div class="title">  LOG DE MANUTENÇÃO</div>
                <div class="title">  $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</div>
                <div class="title">  Modo: $Mode</div>
                <div class="title">═══════════════════════════════════════</div>
                <br>
"@
    
    foreach ($log in $MaintenanceLog) {
        $class = if ($log -match "✓") { "success" } elseif ($log -match "✗|⚠") { "error" } elseif ($log -match "===") { "title" } else { "" }
        $HTML += "                <div class='$class'>$log</div>`n"
    }
    
    $HTML += @"
                <br>
                <div class="title">═══════════════════════════════════════</div>
                <div class="success">✓ Concluído!</div>
            </div>
        </div>
"@
}

# INFO GERAL
$HTML += @"
        <div class="info-grid" id="info-geral">
            <div style="grid-column: 1 / -1; padding: 10px 20px; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 5px; margin-bottom: 10px;">
                <h2 style="margin: 0; color: white;">💻 Informações Gerais</h2>
            </div>

            <div class="info-card">
                <h3>💻 Sistema Operacional</h3>
                <div class="info-row"><span class="info-label">Sistema:</span><span class="info-value">$(Format-SafeValue $OSInfo.Caption)</span></div>
                <div class="info-row"><span class="info-label">Versão:</span><span class="info-value">$(Format-SafeValue $OSInfo.Version)</span></div>
                <div class="info-row"><span class="info-label">Build:</span><span class="info-value">$(Format-SafeValue $OSInfo.BuildNumber)</span></div>
                <div class="info-row"><span class="info-label">Arquitetura:</span><span class="info-value">$(Format-SafeValue $OSInfo.OSArchitecture)</span></div>
                <div class="info-row"><span class="info-label">Instalado em:</span><span class="info-value">$(if($OSInfo.InstallDate){$OSInfo.InstallDate.ToString('dd/MM/yyyy')}else{'N/A'})</span></div>
                <div class="info-row"><span class="info-label">Uptime:</span><span class="info-value">$(if($OSInfo.LastBootUpTime){[math]::Round((New-TimeSpan -Start $OSInfo.LastBootUpTime).TotalHours, 2)}else{0}) horas</span></div>
            </div>

            <div class="info-card">
                <h3>🔧 Hardware</h3>
                <div class="info-row"><span class="info-label">Fabricante:</span><span class="info-value">$(Format-SafeValue $ComputerInfo.CsManufacturer)</span></div>
                <div class="info-row"><span class="info-label">Modelo:</span><span class="info-value">$(Format-SafeValue $ComputerInfo.CsModel)</span></div>
                <div class="info-row"><span class="info-label">Serial BIOS:</span><span class="info-value">$(Format-SafeValue $BIOS.SerialNumber)</span></div>
                <div class="info-row"><span class="info-label">Versão BIOS:</span><span class="info-value">$(Format-SafeValue $BIOS.SMBIOSBIOSVersion)</span></div>
            </div>

            <div class="info-card">
                <h3>⚡ Processador</h3>
                <div class="info-row"><span class="info-label">Modelo:</span><span class="info-value">$(Format-SafeValue $CPU.Name)</span></div>
                <div class="info-row"><span class="info-label">Núcleos:</span><span class="info-value">$(Format-SafeValue $CPU.NumberOfCores) físicos / $(Format-SafeValue $CPU.NumberOfLogicalProcessors) lógicos</span></div>
                <div class="info-row"><span class="info-label">Velocidade:</span><span class="info-value">$(Format-SafeValue $CPU.MaxClockSpeed) MHz</span></div>
                <div class="info-row"><span class="info-label">Cache L3:</span><span class="info-value">$(Format-SafeValue $CPU.L3CacheSize) KB</span></div>
            </div>

            <div class="info-card">
                <h3>💾 Memória RAM</h3>
                <div class="info-row"><span class="info-label">Total:</span><span class="info-value">$(if($TotalRAM -gt 0){[math]::Round($TotalRAM / 1GB, 2)}else{0}) GB</span></div>
                <div class="info-row"><span class="info-label">Em Uso:</span><span class="info-value">$(if($UsedRAM -gt 0){[math]::Round($UsedRAM / 1GB, 2)}else{0}) GB</span></div>
                <div class="info-row"><span class="info-label">Disponível:</span><span class="info-value">$(if($FreeRAM -gt 0){[math]::Round($FreeRAM / 1GB, 2)}else{0}) GB</span></div>
                <div class="info-row"><span class="info-label">Ver Detalhes:</span><span class="info-value"><a href="#ram-details" style="color: #667eea;">👇 Abaixo</a></span></div>
            </div>

            <div class="info-card">
                <h3>🖼️ Vídeo</h3>
"@

if ($GPU.Count -gt 0) {
    foreach ($Card in $GPU) {
        $VRAM = if ($Card.AdapterRAM -gt 0) { [math]::Round($Card.AdapterRAM / 1GB, 2) } else { "N/A" }
        $HTML += @"
                <div class="info-row"><span class="info-label">GPU:</span><span class="info-value">$(Format-SafeValue $Card.Name)</span></div>
                <div class="info-row"><span class="info-label">VRAM:</span><span class="info-value">$VRAM GB</span></div>
                <div class="info-row"><span class="info-label">Driver:</span><span class="info-value">$(Format-SafeValue $Card.DriverVersion)</span></div>
"@
    }
} else {
    $HTML += '<div class="no-data">N/A</div>'
}

$HTML += @"
            </div>

	<div class="info-card">
                <h3>🌐 Rede</h3>
"@

if ($NetworkAdapters.Count -gt 0) {
    foreach ($Adapter in ($NetworkAdapters | Select-Object -First 2)) {
        # Buscar IP do adaptador
        $AdapterIP = "N/A"
        $AdapterConfig = $IPConfig | Where-Object { $_.InterfaceAlias -eq $Adapter.Name }
        if ($AdapterConfig -and $AdapterConfig.IPv4Address) {
            $AdapterIP = $AdapterConfig.IPv4Address.IPAddress
        }
        
        $HTML += @"
                <div class="info-row"><span class="info-label">Adaptador:</span><span class="info-value">$(Format-SafeValue $Adapter.InterfaceDescription)</span></div>
                <div class="info-row"><span class="info-label">Status:</span><span class="info-value"><span class="badge badge-success">$(Format-SafeValue $Adapter.Status)</span></span></div>
                <div class="info-row"><span class="info-label">IP (IPv4):</span><span class="info-value"><strong>$AdapterIP</strong></span></div>
                <div class="info-row"><span class="info-label">MAC Address:</span><span class="info-value"><strong>$(Format-SafeValue $Adapter.MacAddress)</strong></span></div>
                <div class="info-row"><span class="info-label">Velocidade:</span><span class="info-value">$(Format-SafeValue $Adapter.LinkSpeed)</span></div>
"@
    }
} else {
    $HTML += '<div class="no-data">N/A</div>'
}

$HTML += @"
            </div>
        </div>

        <!-- RAM DESTACADA -->
        <div class="section" id="ram-details">
            <h2>💾 Análise Detalhada da RAM</h2>
            
            <div style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; color: white;">
                <h3 style="color: white; border: none; margin: 0 0 20px 0; font-size: 1.8em;">🎯 Status da Memória</h3>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Total</div>
                        <div style="font-size: 2em; font-weight: bold;">$(if($TotalRAM -gt 0){[math]::Round($TotalRAM / 1GB, 1)}else{0}) GB</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Em Uso</div>
                        <div style="font-size: 2em; font-weight: bold;">$(if($UsedRAM -gt 0){[math]::Round($UsedRAM / 1GB, 1)}else{0}) GB</div>
                        <div style="font-size: 0.85em; opacity: 0.8;">($RAMUsedPercent%)</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Disponível</div>
                        <div style="font-size: 2em; font-weight: bold;">$(if($FreeRAM -gt 0){[math]::Round($FreeRAM / 1GB, 1)}else{0}) GB</div>
                        <div style="font-size: 0.85em; opacity: 0.8;">($RAMFreePercent%)</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Status</div>
                        <div style="font-size: 1.5em; font-weight: bold;">$(if($RAMUsedPercent -gt 90){"❌"}elseif($RAMUsedPercent -gt 75){"⚠️"}else{"✅"})</div>
                        <div style="font-size: 0.9em;">$(if($RAMUsedPercent -gt 90){"Crítico"}elseif($RAMUsedPercent -gt 75){"Alto"}else{"Normal"})</div>
                    </div>
                </div>
                
                <div style="margin-top: 20px;">
                    <div style="width: 100%; height: 30px; background: rgba(255,255,255,0.2); border-radius: 15px; overflow: hidden;">
                        <div style="height: 100%; width: $RAMUsedPercent%; background: linear-gradient(90deg, $(if($RAMUsedPercent -gt 90){"#e74c3c"}elseif($RAMUsedPercent -gt 75){"#f39c12"}else{"#3498db"}) 0%, $(if($RAMUsedPercent -gt 90){"#c0392b"}elseif($RAMUsedPercent -gt 75){"#e67e22"}else{"#2980b9"}) 100%); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                            $RAMUsedPercent% Em Uso
                        </div>
                    </div>
                </div>
"@

if ($RAMUsedPercent -gt 75) {
    $HTML += @"
                <div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.15); border-left: 4px solid #fff; border-radius: 5px;">
                    <div style="font-weight: bold; margin-bottom: 8px;">💡 Recomendações:</div>
                    <ul style="margin: 0; padding-left: 20px; font-size: 0.9em;">
"@
    if ($RAMUsedPercent -gt 90) {
        $HTML += "<li>ATENÇÃO: Uso crítico! Feche programas imediatamente</li><li>Considere adicionar mais RAM</li><li>Reinicie o computador</li>"
    } else {
        $HTML += "<li>Uso elevado detectado</li><li>Monitore programas em segundo plano</li>"
    }
    $HTML += "</ul></div>"
}

$HTML += @"
            </div>

            <h3 style="color: #2c3e50;">Módulos Instalados</h3>
            <table>
                <thead><tr><th>Slot</th><th>Capacidade</th><th>Velocidade</th><th>Tipo</th><th>Fabricante</th></tr></thead>
                <tbody>
"@

if ($RAM.Count -gt 0) {
    $SlotIndex = 1
    foreach ($Module in $RAM) {
        $Cap = if ($Module.Capacity) { [math]::Round($Module.Capacity / 1GB) } else { "N/A" }
        $Spd = Format-SafeValue $Module.Speed
        $Type = switch ($Module.MemoryType) { 20 {"DDR"} 21 {"DDR2"} 24 {"DDR3"} 26 {"DDR4"} 34 {"DDR5"} default {"?"} }
        $HTML += "<tr><td><strong>Slot $SlotIndex</strong></td><td>$Cap GB</td><td>$Spd MHz</td><td>$Type</td><td>$(Format-SafeValue $Module.Manufacturer)</td></tr>"
        $SlotIndex++
    }
} else {
    $HTML += '<tr><td colspan="5" class="no-data">N/A</td></tr>'
}

$HTML += "</tbody></table></div>"

# DISCO C
$HTML += @"
        <!-- DISCO C -->
        <div class="section" id="disco-c">
            <h2>💿 Armazenamento</h2>
"@

$DriveC = $Volumes | Where-Object { $_.DriveLetter -eq 'C' }
if ($DriveC) {
    $UsedC = $DriveC.Size - $DriveC.SizeRemaining
    $UsedPercentC = [math]::Round(($UsedC / $DriveC.Size) * 100, 1)
    $FreePercentC = [math]::Round(($DriveC.SizeRemaining / $DriveC.Size) * 100, 1)
    $StatusColorC = if ($UsedPercentC -gt 90) { "#e74c3c" } elseif ($UsedPercentC -gt 75) { "#f39c12" } else { "#27ae60" }
    $StatusTextC = if ($UsedPercentC -gt 90) { "CRÍTICO" } elseif ($UsedPercentC -gt 75) { "AVISO" } else { "Normal" }
    $StatusIconC = if ($UsedPercentC -gt 90) { "❌" } elseif ($UsedPercentC -gt 75) { "⚠️" } else { "✅" }
    
    $HTML += @"
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; color: white;">
                <h3 style="color: white; border: none; margin: 0 0 20px 0; font-size: 1.8em;">🖥️ Disco C:</h3>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Total</div>
                        <div style="font-size: 2em; font-weight: bold;">$([math]::Round($DriveC.Size / 1GB, 1)) GB</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Usado</div>
                        <div style="font-size: 2em; font-weight: bold;">$([math]::Round($UsedC / 1GB, 1)) GB</div>
                        <div style="font-size: 0.85em; opacity: 0.8;">($UsedPercentC%)</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Livre</div>
                        <div style="font-size: 2em; font-weight: bold; color: $StatusColorC;">$([math]::Round($DriveC.SizeRemaining / 1GB, 1)) GB</div>
                        <div style="font-size: 0.85em; opacity: 0.8;">($FreePercentC%)</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
                        <div style="font-size: 0.9em; opacity: 0.9; margin-bottom: 5px;">Status</div>
                        <div style="font-size: 1.5em; font-weight: bold;">$StatusIconC</div>
                        <div style="font-size: 0.9em;">$StatusTextC</div>
                    </div>
                </div>
                
                <div style="margin-top: 20px;">
                    <div style="width: 100%; height: 30px; background: rgba(255,255,255,0.2); border-radius: 15px; overflow: hidden;">
                        <div style="height: 100%; width: $UsedPercentC%; background: linear-gradient(90deg, $StatusColorC 0%, $(if($UsedPercentC -gt 90){"#c0392b"}elseif($UsedPercentC -gt 75){"#e67e22"}else{"#2ecc71"}) 100%); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold;">
                            $UsedPercentC% Usado
                        </div>
                    </div>
                </div>
"@

    if ($UsedPercentC -gt 75) {
        $HTML += @"
                <div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.15); border-left: 4px solid #fff; border-radius: 5px;">
                    <div style="font-weight: bold; margin-bottom: 8px;">⚠️ Recomendações:</div>
                    <ul style="margin: 0; padding-left: 20px; font-size: 0.9em;">
"@
        if ($UsedPercentC -gt 90) {
            $HTML += "<li>URGENTE: Libere espaço imediatamente!</li><li>Execute Limpeza de Disco</li><li>Desinstale programas não usados</li><li>Esvazie a Lixeira</li>"
        } else {
            $HTML += "<li>Considere liberar espaço em breve</li><li>Execute limpeza de temporários</li>"
        }
        $HTML += "</ul></div>"
    }
    
    $HTML += "</div>"
}

# TODOS OS DISCOS
$HTML += @"
            <h3 style="color: #2c3e50;" id="armazenamento">Todos os Discos</h3>
"@

if ($Disks.Count -gt 0) {
    $HTML += @"
            <table>
                <thead><tr><th>Disco</th><th>Modelo</th><th>Tamanho</th><th>Interface</th><th>Tipo</th><th>Status</th></tr></thead>
                <tbody>
"@
    
    foreach ($Disk in $Disks) {
        $DiskSize = if ($Disk.Size -gt 0) { [math]::Round($Disk.Size / 1GB, 2) } else { "N/A" }
        $MediaType = "N/A"
        $PhysicalDisk = $PhysicalDisks | Where-Object { $_.DeviceId -eq $Disk.Index }
        if ($PhysicalDisk) {
            $MediaType = switch ($PhysicalDisk.MediaType) {
                "SSD" { "SSD" }
                "HDD" { "HDD" }
                default { $PhysicalDisk.MediaType }
            }
        }
        
        $HTML += "<tr><td>$(Format-SafeValue $Disk.DeviceID)</td><td>$(Format-SafeValue $Disk.Model)</td><td>$DiskSize GB</td><td>$(Format-SafeValue $Disk.InterfaceType)</td><td><span class='badge badge-info'>$MediaType</span></td><td><span class='badge badge-success'>$(Format-SafeValue $Disk.Status)</span></td></tr>"
    }
    
    $HTML += "</tbody></table>"
}

# VOLUMES
if ($Volumes.Count -gt 0) {
    $HTML += @"
            <h3 style="margin-top: 30px; color: #2c3e50;">Volumes</h3>
            <table>
                <thead><tr><th>Letra</th><th>Label</th><th>Sistema</th><th>Total</th><th>Livre</th><th>Uso</th></tr></thead>
                <tbody>
"@
    
    foreach ($Volume in $Volumes) {
        if ($Volume.Size -gt 0) {
            $UsedPercent = [math]::Round((($Volume.Size - $Volume.SizeRemaining) / $Volume.Size) * 100, 1)
            $BadgeClass = if ($UsedPercent -gt 90) { "badge-danger" } elseif ($UsedPercent -gt 75) { "badge-warning" } else { "badge-success" }
            $ProgressClass = if ($UsedPercent -gt 90) { "progress-danger" } elseif ($UsedPercent -gt 75) { "progress-warning" } else { "progress-normal" }
            
            $HTML += @"
                    <tr>
                        <td>$(Format-SafeValue $Volume.DriveLetter):\</td>
                        <td>$(Format-SafeValue $Volume.FileSystemLabel)</td>
                        <td>$(Format-SafeValue $Volume.FileSystem)</td>
                        <td>$([math]::Round($Volume.Size / 1GB, 2)) GB</td>
                        <td>$([math]::Round($Volume.SizeRemaining / 1GB, 2)) GB</td>
                        <td>
                            <span class="badge $BadgeClass">$UsedPercent%</span>
                            <div class="progress-bar"><div class="progress-fill $ProgressClass" style="width: $UsedPercent%"></div></div>
                        </td>
                    </tr>
"@
        }
    }
    
    $HTML += "</tbody></table>"
}

$HTML += "</div>"

# SOFTWARE
$HTML += @"
        <!-- SOFTWARE -->
        <div class="section" id="software">
            <h2>📦 Software Instalado</h2>
"@

if ($InstalledSoftware.Count -gt 0) {
    $HTML += @"
            <p style="margin-bottom: 15px; color: #666;">Total: <strong>$($InstalledSoftware.Count)</strong> programas</p>
            <table>
                <thead><tr><th>Programa</th><th>Versão</th><th>Fabricante</th><th>Data</th></tr></thead>
                <tbody>
"@
    
    foreach ($Software in ($InstalledSoftware | Select-Object -First 100)) {
        $InstallDateFormatted = if ($Software.InstallDate) { 
            try { [datetime]::ParseExact($Software.InstallDate, 'yyyyMMdd', $null).ToString('dd/MM/yyyy') } 
            catch { Format-SafeValue $Software.InstallDate }
        } else { "N/A" }
        
        $HTML += "<tr><td>$(Format-SafeValue $Software.DisplayName)</td><td>$(Format-SafeValue $Software.DisplayVersion)</td><td>$(Format-SafeValue $Software.Publisher)</td><td>$InstallDateFormatted</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">Nenhum software detectado</div>'
}

$HTML += "</div>"

# PROCESSOS
$HTML += @"
        <!-- PROCESSOS -->
        <div class="section" id="processos">
            <h2>⚙️ Processos (Top 30)</h2>
"@

if ($Processes.Count -gt 0) {
    $HTML += @"
            <table>
                <thead><tr><th>Nome</th><th>PID</th><th>CPU (s)</th><th>Memória (MB)</th><th>Threads</th></tr></thead>
                <tbody>
"@
    
    foreach ($Process in $Processes) {
        $CPUTime = if ($Process.CPU) { [math]::Round($Process.CPU, 2) } else { 0 }
        $Memory = if ($Process.WorkingSet) { [math]::Round($Process.WorkingSet / 1MB, 2) } else { 0 }
        $Threads = if ($Process.Threads) { $Process.Threads.Count } else { 0 }
        
        $HTML += "<tr><td>$(Format-SafeValue $Process.ProcessName)</td><td>$(Format-SafeValue $Process.Id)</td><td>$CPUTime</td><td>$Memory</td><td>$Threads</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">N/A</div>'
}

$HTML += "</div>"

# SERVIÇOS
$HTML += @"
        <!-- SERVIÇOS -->
        <div class="section" id="servicos">
            <h2>🔄 Serviços Windows</h2>
"@

if ($Services.Count -gt 0) {
    $RunningServices = ($Services | Where-Object {$_.Status -eq "Running"}).Count
    $StoppedServices = ($Services | Where-Object {$_.Status -eq "Stopped"}).Count
    
    $HTML += @"
            <p style="margin-bottom: 15px;">
                <span class="badge badge-success">$RunningServices Rodando</span>
                <span class="badge badge-warning">$StoppedServices Parados</span>
                <span class="badge badge-info">$($Services.Count) Total</span>
            </p>
            <table>
                <thead><tr><th>Serviço</th><th>Nome</th><th>Status</th><th>Inicialização</th></tr></thead>
                <tbody>
"@
    
    foreach ($Service in ($Services | Select-Object -First 100)) {
        $StatusClass = if ($Service.Status -eq "Running") { "status-ok" } else { "status-warning" }
        $HTML += "<tr><td>$(Format-SafeValue $Service.Name)</td><td>$(Format-SafeValue $Service.DisplayName)</td><td class='$StatusClass'>$(Format-SafeValue $Service.Status)</td><td>$(Format-SafeValue $Service.StartType)</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">N/A</div>'
}

$HTML += "</div>"

# ATUALIZAÇÕES
$HTML += @"
        <!-- ATUALIZAÇÕES -->
        <div class="section" id="atualizacoes">
            <h2>🔄 Atualizações Windows</h2>
"@

if ($Updates.Count -gt 0) {
    $HTML += @"
            <p style="margin-bottom: 15px;">Últimas <strong>$($Updates.Count)</strong> atualizações</p>
            <table>
                <thead><tr><th>KB</th><th>Descrição</th><th>Data</th><th>Instalado Por</th></tr></thead>
                <tbody>
"@
    
    foreach ($Update in $Updates) {
        $InstallDate = if ($Update.InstalledOn) { $Update.InstalledOn.ToString('dd/MM/yyyy') } else { "N/A" }
        $HTML += "<tr><td>$(Format-SafeValue $Update.HotFixID)</td><td>$(Format-SafeValue $Update.Description)</td><td>$InstallDate</td><td>$(Format-SafeValue $Update.InstalledBy)</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">N/A</div>'
}

$HTML += "</div>"

# CONECTIVIDADE
$HTML += @"
        <!-- CONECTIVIDADE -->
        <div class="section" id="conectividade">
            <h2>🌐 Conectividade</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>Status</h3>
                    <div class="info-row"><span class="info-label">Google DNS:</span><span class="info-value">$(if($PingGoogle){"<span class='status-ok'>✓ Online</span>"}else{"<span class='status-error'>✗ Offline</span>"})</span></div>
                    <div class="info-row"><span class="info-label">DNS:</span><span class="info-value">$(if($PingDNS){"<span class='status-ok'>✓ OK</span>"}else{"<span class='status-error'>✗ Erro</span>"})</span></div>
                    <div class="info-row"><span class="info-label">Velocidade:</span><span class="info-value">$(if($InternetSpeed -gt 0){"~$InternetSpeed Mbps"}else{"N/A"})</span></div>
                </div>
            </div>
        </div>
"@

# TEMPERATURA
if ($Temperature) {
    $TempColor = if ($Temperature -gt 80) { "#e74c3c" } elseif ($Temperature -gt 60) { "#f39c12" } else { "#27ae60" }
    $TempStatus = if ($Temperature -gt 80) { "CRÍTICO" } elseif ($Temperature -gt 60) { "ELEVADO" } else { "NORMAL" }
    
    $HTML += @"
        <div class="section" id="temperatura">
            <h2>🌡️ Temperatura</h2>
            <div style="background: linear-gradient(135deg, $TempColor 0%, $(if($Temperature -gt 80){"#c0392b"}elseif($Temperature -gt 60){"#e67e22"}else{"#2ecc71"}) 100%); padding: 30px; border-radius: 10px; color: white; text-align: center;">
                <div style="font-size: 3em; font-weight: bold; margin-bottom: 10px;">$Temperature°C</div>
                <div style="font-size: 1.2em;">Status: $TempStatus</div>
"@
    
    if ($Temperature -gt 70) {
        $HTML += @"
                <div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.2); border-radius: 5px; text-align: left;">
                    <strong>⚠️ Atenção:</strong> Temperatura elevada!
                    <ul style="margin-top: 10px; padding-left: 20px;">
                        <li>Verifique ventoinhas</li>
                        <li>Limpe o pó</li>
                        <li>Melhore a ventilação</li>
                    </ul>
                </div>
"@
    }
    
    $HTML += "</div></div>"
}

# FIREWALL
$HTML += @"
        <!-- FIREWALL -->
        <div class="section" id="firewall">
            <h2>🛡️ Firewall</h2>
"@

if ($FirewallProfile.Count -gt 0) {
    $HTML += @"
            <table>
                <thead><tr><th>Perfil</th><th>Estado</th><th>Entrada</th><th>Saída</th></tr></thead>
                <tbody>
"@
    
    foreach ($Profile in $FirewallProfile) {
        $StateClass = if ($Profile.Enabled) { "status-ok" } else { "status-error" }
        $HTML += "<tr><td>$(Format-SafeValue $Profile.Name)</td><td class='$StateClass'>$(if($Profile.Enabled){"Ativado"}else{"Desativado"})</td><td>$(Format-SafeValue $Profile.DefaultInboundAction)</td><td>$(Format-SafeValue $Profile.DefaultOutboundAction)</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">N/A</div>'
}

$HTML += "</div>"

# EVENTOS
$HTML += @"
        <!-- EVENTOS -->
        <div class="section" id="eventos">
            <h2>⚠️ Eventos Críticos</h2>
            <h3 style="margin-top: 20px; color: #2c3e50;">Sistema</h3>
"@

if ($SystemErrors.Count -gt 0) {
    $HTML += @"
            <table>
                <thead><tr><th>Data</th><th>Origem</th><th>ID</th><th>Mensagem</th></tr></thead>
                <tbody>
"@
    
    foreach ($Event in $SystemErrors) {
        $EventTime = if ($Event.TimeGenerated) { $Event.TimeGenerated.ToString('dd/MM/yy HH:mm') } 
                     elseif ($Event.TimeCreated) { $Event.TimeCreated.ToString('dd/MM/yy HH:mm') } else { "N/A" }
        $EventSource = if ($Event.Source) { $Event.Source } elseif ($Event.ProviderName) { $Event.ProviderName } else { "N/A" }
        $EventMsg = if ($Event.Message) { $Event.Message.Substring(0, [Math]::Min(150, $Event.Message.Length)) } else { "N/A" }
        
        $HTML += "<tr><td>$EventTime</td><td>$EventSource</td><td>$(Format-SafeValue $Event.EventID)</td><td>$EventMsg...</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">Nenhum erro recente</div>'
}

$HTML += @"
            <h3 style="margin-top: 30px; color: #2c3e50;">Aplicação</h3>
"@

if ($ApplicationErrors.Count -gt 0) {
    $HTML += @"
            <table>
                <thead><tr><th>Data</th><th>Origem</th><th>ID</th><th>Mensagem</th></tr></thead>
                <tbody>
"@
    
    foreach ($Event in $ApplicationErrors) {
        $EventTime = if ($Event.TimeGenerated) { $Event.TimeGenerated.ToString('dd/MM/yy HH:mm') } 
                     elseif ($Event.TimeCreated) { $Event.TimeCreated.ToString('dd/MM/yy HH:mm') } else { "N/A" }
        $EventSource = if ($Event.Source) { $Event.Source } elseif ($Event.ProviderName) { $Event.ProviderName } else { "N/A" }
        $EventMsg = if ($Event.Message) { $Event.Message.Substring(0, [Math]::Min(150, $Event.Message.Length)) } else { "N/A" }
        
        $HTML += "<tr><td>$EventTime</td><td>$EventSource</td><td>$(Format-SafeValue $Event.EventID)</td><td>$EventMsg...</td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">Nenhum erro recente</div>'
}

$HTML += "</div>"

# DRIVERS
if ($OutdatedDrivers.Count -gt 0) {
    $HTML += @"
        <div class="section" id="drivers">
            <h2>⚠️ Drivers Desatualizados</h2>
            <p style="margin-bottom: 15px;">Encontrados <strong>$($OutdatedDrivers.Count)</strong> drivers com +2 anos</p>
            <table>
                <thead><tr><th>Driver</th><th>Versão</th><th>Provedor</th><th>Data</th><th>Status</th></tr></thead>
                <tbody>
"@
    
    foreach ($Driver in $OutdatedDrivers) {
        $DriverDate = if ($Driver.Date) { $Driver.Date.ToString('dd/MM/yyyy') } else { "N/A" }
        $HTML += "<tr><td>$(Format-SafeValue $Driver.Driver)</td><td>$(Format-SafeValue $Driver.Version)</td><td>$(Format-SafeValue $Driver.ProviderName)</td><td>$DriverDate</td><td><span class='badge badge-warning'>Antigo</span></td></tr>"
    }
    
    $HTML += @"
                </tbody>
            </table>
            <div style="margin-top: 15px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px;">
                <strong>💡 Dica:</strong> Use Windows Update ou site do fabricante
            </div>
        </div>
"@
}

# USB
$HTML += @"
        <!-- USB -->
        <div class="section" id="usb">
            <h2>🔌 Dispositivos USB</h2>
"@

if ($USBDevices.Count -gt 0) {
    $HTML += @"
            <table>
                <thead><tr><th>Dispositivo</th><th>Fabricante</th><th>Status</th></tr></thead>
                <tbody>
"@
    
    foreach ($Device in ($USBDevices | Select-Object -First 30)) {
        $HTML += "<tr><td>$(Format-SafeValue $Device.FriendlyName)</td><td>$(Format-SafeValue $Device.Manufacturer)</td><td><span class='badge badge-success'>$(Format-SafeValue $Device.Status)</span></td></tr>"
    }
    
    $HTML += "</tbody></table>"
} else {
    $HTML += '<div class="no-data">Nenhum dispositivo USB</div>'
}

$HTML += "</div>"

# BATERIA COMPLETA
if ($Battery) {
    $DesignCapacity = if ($BatteryStaticData) { $BatteryStaticData.DesignedCapacity } else { $Battery.DesignCapacity }
    $FullChargeCapacity = if ($BatteryStatus) { $BatteryStatus.FullChargedCapacity } else { 0 }
    
    $BatteryHealth = if ($DesignCapacity -and $FullChargeCapacity -and $DesignCapacity -gt 0) {
        [math]::Round(($FullChargeCapacity / $DesignCapacity) * 100, 1)
    } else { "N/A" }
    
    $CycleCount = if ($BatteryCycleCount) { $BatteryCycleCount.CycleCount } else { "N/A" }
    
    $BatteryStatusText = switch ($Battery.BatteryStatus) {
        1 { "Descarregando" }
        2 { "Conectado (AC)" }
        3 { "Totalmente Carregado" }
        4 { "Baixa" }
        5 { "Crítica" }
        6 { "Carregando" }
        default { "Desconhecido" }
    }
    
    $ChemistryText = switch ($Battery.Chemistry) {
        1 { "Outro" }
        2 { "Desconhecido" }
        3 { "Chumbo Ácido" }
        4 { "Níquel Cádmio" }
        5 { "Níquel Metal Hidreto" }
        6 { "Íon de Lítio" }
        7 { "Zinco Ar" }
        8 { "Polímero de Lítio" }
        default { "Não especificado" }
    }
    
    $HTML += @"
        <div class="section" id="bateria">
            <h2>🔋 Bateria - Análise Completa</h2>
            
            <div class="info-grid">
                <div class="info-card">
                    <h3>Status Atual</h3>
                    <div class="info-row"><span class="info-label">Dispositivo:</span><span class="info-value">$(Format-SafeValue $Battery.Name)</span></div>
                    <div class="info-row"><span class="info-label">Status:</span><span class="info-value"><span class="badge badge-info">$BatteryStatusText</span></span></div>
                    <div class="info-row"><span class="info-label">Carga:</span><span class="info-value"><strong>$(Format-SafeValue $Battery.EstimatedChargeRemaining)%</strong></span></div>
                    <div class="info-row"><span class="info-label">Tempo Restante:</span><span class="info-value">$(if($Battery.EstimatedRunTime -and $Battery.EstimatedRunTime -ne 71582788){[math]::Round($Battery.EstimatedRunTime / 60, 1)}else{"N/A"}) horas</span></div>
                </div>

                <div class="info-card">
                    <h3>Saúde</h3>
                    <div class="info-row"><span class="info-label">Saúde:</span><span class="info-value"><strong style="font-size: 1.2em; color: $(if($BatteryHealth -ne "N/A" -and $BatteryHealth -gt 80){"#27ae60"}elseif($BatteryHealth -ne "N/A" -and $BatteryHealth -gt 50){"#f39c12"}else{"#e74c3c"})">$BatteryHealth%</strong></span></div>
                    <div class="info-row"><span class="info-label">Design:</span><span class="info-value">$(if($DesignCapacity){[math]::Round($DesignCapacity / 1000, 2)}else{"N/A"}) Wh</span></div>
                    <div class="info-row"><span class="info-label">Carga Atual:</span><span class="info-value">$(if($FullChargeCapacity){[math]::Round($FullChargeCapacity / 1000, 2)}else{"N/A"}) Wh</span></div>
                    <div class="info-row"><span class="info-label">Ciclos:</span><span class="info-value">$(Format-SafeValue $CycleCount)</span></div>
                </div>

                <div class="info-card">
                    <h3>Especificações</h3>
                    <div class="info-row"><span class="info-label">Química:</span><span class="info-value">$ChemistryText</span></div>
                    <div class="info-row"><span class="info-label">Fabricante:</span><span class="info-value">$(Format-SafeValue $BatteryStaticData.ManufactureName)</span></div>
                    <div class="info-row"><span class="info-label">Serial:</span><span class="info-value">$(Format-SafeValue $BatteryStaticData.SerialNumber)</span></div>
                    <div class="info-row"><span class="info-label">Voltagem:</span><span class="info-value">$(if($Battery.DesignVoltage){[math]::Round($Battery.DesignVoltage / 1000, 2)}else{"N/A"}) V</span></div>
                </div>
            </div>

            <h3 style="margin-top: 30px; color: #2c3e50;">Histórico e Degradação</h3>
            <table>
                <thead><tr><th>Métrica</th><th>Original</th><th>Atual</th><th>Degradação</th><th>Status</th></tr></thead>
                <tbody>
                    <tr>
                        <td><strong>Capacidade</strong></td>
                        <td>$(if($DesignCapacity){[math]::Round($DesignCapacity / 1000, 2)}else{"N/A"}) Wh</td>
                        <td>$(if($FullChargeCapacity){[math]::Round($FullChargeCapacity / 1000, 2)}else{"N/A"}) Wh</td>
                        <td>$(if($BatteryHealth -ne "N/A"){[math]::Round(100 - $BatteryHealth, 1)}else{"N/A"})%</td>
                        <td>
"@

    if ($BatteryHealth -ne "N/A") {
        if ($BatteryHealth -gt 85) {
            $HTML += '<span class="badge badge-success">Excelente</span>'
        } elseif ($BatteryHealth -gt 70) {
            $HTML += '<span class="badge badge-info">Boa</span>'
        } elseif ($BatteryHealth -gt 50) {
            $HTML += '<span class="badge badge-warning">Razoável</span>'
        } else {
            $HTML += '<span class="badge badge-danger">Crítica</span>'
        }
    } else {
        $HTML += '<span class="badge badge-info">N/A</span>'
    }

    $HTML += @"
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Ciclos</strong></td>
                        <td colspan="2">$(Format-SafeValue $CycleCount) ciclos</td>
                        <td colspan="2">
"@

    if ($CycleCount -ne "N/A") {
        if ($CycleCount -lt 300) {
            $HTML += '<span class="badge badge-success">Nova</span>'
        } elseif ($CycleCount -lt 500) {
            $HTML += '<span class="badge badge-info">Normal</span>'
        } elseif ($CycleCount -lt 800) {
            $HTML += '<span class="badge badge-warning">Uso Intenso</span>'
        } else {
            $HTML += '<span class="badge badge-danger">Considerar Troca</span>'
        }
    } else {
        $HTML += '<span class="badge badge-info">N/A</span>'
    }

    $HTML += @"
                        </td>
                    </tr>
                </tbody>
            </table>

            <div style="margin-top: 20px; padding: 15px; background: #e8f4f8; border-left: 4px solid #3498db; border-radius: 5px;">
                <h4 style="margin: 0 0 10px 0; color: #2c3e50;">💡 Dicas de Preservação:</h4>
                <ul style="margin: 0; padding-left: 20px; color: #555;">
                    <li>Mantenha carga entre 20-80%</li>
                    <li>Evite deixar na tomada o tempo todo</li>
                    <li>Evite ciclos 0-100% frequentes</li>
                    <li>Considere trocar se saúde < 60%</li>
                    <li>Mantenha sistema atualizado</li>
                </ul>
            </div>
"@

    # BATTERY REPORT COMPLETO EMBUTIDO
    if ($BatteryReportGenerated -and $BatteryReportHTML) {
        $HTML += @"
            <h3 style="margin-top: 30px; color: #2c3e50;">📊 Battery Report Completo do Windows</h3>
            <div style="margin-top: 20px; padding: 20px; background: #f8f9fa; border-radius: 10px; border: 2px solid #667eea;">
                <p style="margin-bottom: 15px; color: #666;">
                    <strong>ℹ️ Relatório oficial do Windows PowerCfg</strong> - 
                    Gerado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
                </p>
                <details style="cursor: pointer;">
                    <summary style="padding: 10px; background: #667eea; color: white; border-radius: 5px; font-weight: bold;">
                        🔍 Clique para ver o Battery Report completo
                    </summary>
                    <div style="margin-top: 15px; max-height: 600px; overflow-y: auto; background: white; padding: 15px; border-radius: 5px; border: 1px solid #ddd;">
                        $BatteryReportHTML
                    </div>
                </details>
            </div>
"@
    } else {
        $HTML += @"
            <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 5px;">
                <strong>ℹ️ Battery Report do Windows não disponível</strong><br>
                Execute como Administrador para gerar relatório completo
            </div>
"@
    }

    $HTML += "</div>"
}

# RESUMO FINAL
$HTML += @"
        <div class="section" id="resumo" style="background: #f8f9fa;">
            <h2>📊 Resumo do Diagnóstico</h2>
            <div class="info-grid">
                <div class="info-card">
                    <h3>✅ Estatísticas</h3>
                    <div class="info-row"><span class="info-label">SO:</span><span class="info-value">$(Format-SafeValue $OSInfo.Caption)</span></div>
                    <div class="info-row"><span class="info-label">CPU:</span><span class="info-value">$(Format-SafeValue $CPU.Name)</span></div>
                    <div class="info-row"><span class="info-label">RAM:</span><span class="info-value">$(if($TotalRAM -gt 0){[math]::Round($TotalRAM / 1GB, 2)}else{0}) GB</span></div>
                    <div class="info-row"><span class="info-label">Discos:</span><span class="info-value">$($Disks.Count)</span></div>
                    <div class="info-row"><span class="info-label">Programas:</span><span class="info-value">$($InstalledSoftware.Count)</span></div>
                    <div class="info-row"><span class="info-label">Serviços Ativos:</span><span class="info-value">$(($Services | Where-Object {$_.Status -eq "Running"}).Count)</span></div>
                    <div class="info-row"><span class="info-label">Erros Sistema:</span><span class="info-value">$($SystemErrors.Count)</span></div>
                </div>
            </div>
        </div>

        <!-- FOOTER -->
        <footer>
            <p><strong>Relatório v4.0 Ultra Definitiva</strong></p>
            <p>Tempo de execução: $([math]::Round($StopWatch.Elapsed.TotalSeconds, 2)) segundos</p>
            <p>Modo: $(if($IsAdmin){"✓ Administrador"}else{"⚠ Usuário"}) | Tipo: $Mode</p>
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.2);">
                <p style="font-size: 1.1em; margin-bottom: 10px;">
                    <strong>Desenvolvido por Wilton Lima</strong>
                </p>
                <p style="margin-bottom: 15px;">
                    💻 Especialista em Suporte Técnico e Automação
                </p>
                <div style="display: flex; justify-content: center; gap: 20px; flex-wrap: wrap;">
                    <a href="https://br.linkedin.com/in/wil-limaofc" target="_blank" style="color: white; text-decoration: none; background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 5px; transition: all 0.3s; display: inline-flex; align-items: center; gap: 8px;">
                        <svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                        </svg>
                        LinkedIn
                    </a>
                    <a href="https://github.com/willimaofc" target="_blank" style="color: white; text-decoration: none; background: rgba(255,255,255,0.2); padding: 10px 20px; border-radius: 5px; transition: all 0.3s; display: inline-flex; align-items: center; gap: 8px;">
                        <svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                        </svg>
                        GitHub
                    </a>
                </div>
            </div>
            <p style="margin-top: 20px; opacity: 0.7; font-size: 0.9em;">
                © $(Get-Date -Format 'yyyy') - Desenvolvido com PowerShell
            </p>
        </footer>
    </div>

    <a href="#" class="back-to-top" title="Voltar ao topo">↑</a>

    <script>
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'p') {
                e.preventDefault();
                window.print();
            }
        });

        document.querySelectorAll('.info-card').forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            setTimeout(() => {
                card.style.transition = 'all 0.5s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 50);
        });

        console.log('%c📊 Diagnóstico v4.0 Ultra', 'color: #667eea; font-size: 20px; font-weight: bold;');
        console.log('✓ Relatório carregado com sucesso!');
        console.log('Modo: $Mode');
        console.log('Tempo: $([math]::Round($StopWatch.Elapsed.TotalSeconds, 2))s');
    </script>
</body>
</html>
"@

# SALVAR E ABRIR
try {
    $HTML | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    $StopWatch.Stop()
    
    Write-Host ""
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ DIAGNÓSTICO v4.0 CONCLUÍDO!" -ForegroundColor Green
    Write-Host "════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "📄 Relatório:" -ForegroundColor Cyan
    Write-Host "   $OutputPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "⏱️  Tempo: $([math]::Round($StopWatch.Elapsed.TotalSeconds, 2))s" -ForegroundColor Cyan
    Write-Host "📊 Tamanho: $([math]::Round((Get-Item $OutputPath).Length / 1KB, 2)) KB" -ForegroundColor Cyan
    Write-Host ""
    
    if ($IsAdmin) {
        Write-Host "✅ Modo Admin - Tudo coletado!" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Modo Usuário - Algumas infos limitadas" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "🌐 Abrindo relatório..." -ForegroundColor Green
    Start-Process $OutputPath
    
    Write-Host ""
    Write-Host "✓ Sucesso!" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "❌ ERRO ao salvar:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    # Tentar local alternativo
    try {
        $AltPath = "C:\Temp\Diagnostico_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null }
        $HTML | Out-File -FilePath $AltPath -Encoding UTF8 -Force
        Write-Host "✓ Salvo em: $AltPath" -ForegroundColor Green
        Start-Process $AltPath
    }
    catch {
        Write-Host "❌ Falha total ao salvar" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Pressione ENTER para sair..." -ForegroundColor Gray
Read-Host
