$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot 'deps'
New-Item -ItemType Directory $dir -Force | Out-Null
$file = Join-Path $dir 'wireguard-amd64-1.1.1.msi'
if (!(Test-Path $file)) { Invoke-WebRequest 'https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi' -OutFile $file }
if ((Get-FileHash $file -Algorithm SHA256).Hash -ne '7BFED60AD61B785C914B38B61555A975488E1D3EC472DBFB2FCDF498FCA75242') { throw 'WireGuard package hash mismatch' }
$sig = Get-AuthenticodeSignature $file
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=WireGuard LLC(?:,|$)') { throw 'WireGuard Authenticode signature invalid' }
Write-Output 'Verified official WireGuard MSI.'
