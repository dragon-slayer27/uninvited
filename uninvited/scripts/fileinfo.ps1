# For each path in the JSON array at -InPath: existence, version info and Authenticode signature.
param(
    [Parameter(Mandatory = $true)][string]$InPath,
    [Parameter(Mandatory = $true)][string]$OutPath
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell 5.1 emits a JSON array as ONE pipeline object; do not wrap it in @().
$paths = (Get-Content -LiteralPath $InPath -Raw -Encoding UTF8) | ConvertFrom-Json
$res = [ordered]@{}

foreach ($p in $paths) {
    if (-not $p -or $res.Contains($p)) { continue }
    $info = [ordered]@{ exists = $false }
    try {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            $fi = Get-Item -LiteralPath $p -Force
            $info.exists = $true
            $info.size = $fi.Length
            $info.modified = $fi.LastWriteTimeUtc.ToString('o')
            $vi = $fi.VersionInfo
            $info.company = $vi.CompanyName
            $info.description = $vi.FileDescription
            $info.product = $vi.ProductName
            $info.version = $vi.ProductVersion
            $info.originalName = $vi.OriginalFilename
            $sig = Get-AuthenticodeSignature -LiteralPath $p
            $info.sigStatus = [string]$sig.Status
            $info.sigType = [string]$sig.SignatureType
            $info.isOsBinary = [bool]$sig.IsOSBinary
            if ($sig.SignerCertificate) { $info.signer = $sig.SignerCertificate.Subject }
        }
    } catch { $info.error = $_.Exception.Message }
    $res[$p] = $info
}

$res | ConvertTo-Json -Depth 4 -Compress | Out-File -LiteralPath $OutPath -Encoding utf8
