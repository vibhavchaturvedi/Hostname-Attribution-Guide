<#
.SYNOPSIS
    Export-SysmonDNS.ps1 - Export Sysmon DNS Query Events
    
.DESCRIPTION
    Exports Sysmon Event ID 22 (DNS Query) events for analysis.
    Provides hostname attribution for DNS queries with process context.
    
.PARAMETER Hours
    Number of hours to look back (default: 24)
    
.PARAMETER OutputPath
    Path for CSV output (default: current directory)
    
.PARAMETER Domain
    Filter for specific domain (supports wildcards)
    
.PARAMETER Process
    Filter for specific process name
    
.EXAMPLE
    .\Export-SysmonDNS.ps1 -Hours 24 -OutputPath C:\Logs
    
.EXAMPLE
    .\Export-SysmonDNS.ps1 -Domain "*malicious*" -Hours 48
    
.EXAMPLE
    .\Export-SysmonDNS.ps1 -Process "powershell.exe"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [int]$Hours = 24,
    
    [Parameter()]
    [string]$OutputPath = ".",
    
    [Parameter()]
    [string]$Domain = "*",
    
    [Parameter()]
    [string]$Process = "*"
)

$ErrorActionPreference = "Stop"

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Running without admin rights. Some events may not be accessible."
}

# Calculate time range
$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "Exporting Sysmon DNS events from last $Hours hours..." -ForegroundColor Cyan
Write-Host "Start time: $StartTime" -ForegroundColor Gray

# Query Sysmon events
try {
    $events = Get-WinEvent -FilterHashTable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 22
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Failed to query Sysmon events. Is Sysmon installed?"
    exit 1
}

if ($null -eq $events -or $events.Count -eq 0) {
    Write-Warning "No Sysmon DNS events found in the specified time range."
    exit 0
}

Write-Host "Found $($events.Count) DNS query events" -ForegroundColor Green

# Parse events
$parsedEvents = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    
    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }
    
    # Extract process name from full path
    $processName = if ($data['Image']) {
        Split-Path $data['Image'] -Leaf
    } else {
        "Unknown"
    }
    
    [PSCustomObject]@{
        TimeCreated   = $event.TimeCreated
        Computer      = $event.MachineName
        ProcessGuid   = $data['ProcessGuid']
        ProcessId     = $data['ProcessId']
        ProcessName   = $processName
        Image         = $data['Image']
        QueryName     = $data['QueryName']
        QueryStatus   = $data['QueryStatus']
        QueryResults  = $data['QueryResults']
        User          = $data['User']
    }
}

# Apply filters
$filtered = $parsedEvents | Where-Object {
    ($_.QueryName -like $Domain) -and ($_.ProcessName -like $Process)
}

Write-Host "Filtered to $($filtered.Count) events" -ForegroundColor Yellow

# Generate output filename
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $OutputPath "sysmon_dns_$timestamp.csv"

# Export to CSV
$filtered | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "Exported to: $outputFile" -ForegroundColor Green

# Display summary statistics
Write-Host "`n=== Summary ===" -ForegroundColor Cyan

Write-Host "`nTop 10 Queried Domains:"
$filtered | Group-Object QueryName | Sort-Object Count -Descending | Select-Object -First 10 | 
    Format-Table @{N='Domain';E={$_.Name}}, Count -AutoSize

Write-Host "`nTop 10 Processes Making DNS Queries:"
$filtered | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 10 | 
    Format-Table @{N='Process';E={$_.Name}}, Count -AutoSize

Write-Host "`nTop 10 Users Making DNS Queries:"
$filtered | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10 | 
    Format-Table @{N='User';E={$_.Name}}, Count -AutoSize

# Check for suspicious patterns
Write-Host "`n=== Suspicious Patterns ===" -ForegroundColor Yellow

# Long domain names (potential DGA)
$longDomains = $filtered | Where-Object { $_.QueryName.Length -gt 50 }
if ($longDomains.Count -gt 0) {
    Write-Host "`nLong domain names (potential DGA):" -ForegroundColor Red
    $longDomains | Select-Object TimeCreated, ProcessName, QueryName | Format-Table -AutoSize
}

# Suspicious TLDs
$suspiciousTLDs = $filtered | Where-Object { 
    $_.QueryName -match '\.(tk|xyz|top|pw|cc|su|bit)$'
}
if ($suspiciousTLDs.Count -gt 0) {
    Write-Host "`nSuspicious TLDs:" -ForegroundColor Red
    $suspiciousTLDs | Select-Object TimeCreated, ProcessName, QueryName | Format-Table -AutoSize
}

# PowerShell/Script DNS queries
$scriptDNS = $filtered | Where-Object {
    $_.ProcessName -in @('powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
}
if ($scriptDNS.Count -gt 0) {
    Write-Host "`nScript engine DNS queries:" -ForegroundColor Red
    $scriptDNS | Select-Object TimeCreated, ProcessName, QueryName | Format-Table -AutoSize
}

Write-Host "`nExport complete!" -ForegroundColor Green
