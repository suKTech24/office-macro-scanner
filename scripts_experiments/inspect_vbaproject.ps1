<#
.SYNOPSIS
    Extract vbaProject.bin from an OOXML file and list its OLE streams with oledir.

.DESCRIPTION
    The document is copied and extracted under %TEMP%, never inside the repo.
    The oledir output is saved as a .txt report in OutDir.

.EXAMPLE
    .\scripts_experiments\inspect_vbaproject.ps1 samples\documents\suspicious.xlsm
#>
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$OutDir = "output"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command oledir -ErrorAction SilentlyContinue)) {
    throw "oledir not found. Activate the venv first: .venv\Scripts\Activate.ps1"
}

$doc  = Get-Item $Path
$name = $doc.BaseName

# Work folder per document, e.g. %TEMP%\macro-look\suspicious
$work = Join-Path $env:TEMP "macro-look\$name"
New-Item -ItemType Directory -Force $work | Out-Null

# Expand-Archive only accepts .zip, so copy with a .zip extension first
$zip = Join-Path $work "$name.zip"
Copy-Item $doc.FullName $zip -Force
Expand-Archive $zip -DestinationPath (Join-Path $work "extracted") -Force

# xl\ for Excel, word\ for Word, ppt\ for PowerPoint, so search instead of hardcoding
$vba = Get-ChildItem (Join-Path $work "extracted") -Recurse -Filter vbaProject.bin |
    Select-Object -First 1
if (-not $vba) {
    throw "No vbaProject.bin in $Path (no macros?)"
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
# Absolute path, because Push-Location below changes what a relative path means
$report = Join-Path (Resolve-Path $OutDir) "$name-oledir.txt"

# Run from the extracted folder with a relative path, so the report shows
# xl\vbaProject.bin and not C:\Users\<name>\AppData\...
Push-Location (Join-Path $work "extracted")
try {
    $relative = Resolve-Path -Relative $vba.FullName
    oledir $relative | Tee-Object -FilePath $report
}
finally {
    Pop-Location
}

Write-Host "`nReport saved to $report"
