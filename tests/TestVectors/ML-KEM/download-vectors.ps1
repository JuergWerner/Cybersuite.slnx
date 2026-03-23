# ML-KEM Test Vector Download Script
# Downloads official NIST ACVP test vectors for ML-KEM-512, ML-KEM-768, and ML-KEM-1024

param(
    [switch]$Force
)

$ErrorActionPreference = "Continue"

# Get the directory where this script is located
if ($PSScriptRoot) {
    $scriptDir = $PSScriptRoot
} else {
    $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}

# NIST ACVP Server base URL
$acvpBaseUrl = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

# BouncyCastle test data base URL
$bcBaseUrl = "https://raw.githubusercontent.com/bcgit/bc-csharp/master/crypto/test/data/pqc"

# Color output helpers
function Write-Success { param($Message) Write-Host $Message -ForegroundColor Green }
function Write-Info { param($Message) Write-Host $Message -ForegroundColor Cyan }
function Write-Warn { param($Message) Write-Host $Message -ForegroundColor Yellow }
function Write-Fail { param($Message) Write-Host $Message -ForegroundColor Red }

Write-Info "=== ML-KEM Test Vector Download ==="
Write-Info ""

# Create directory structure
$parameterSets = @("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")

foreach ($paramSet in $parameterSets) {
    $dir = Join-Path $PSScriptRoot $paramSet
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Success "Created directory: $paramSet"
    } else {
        Write-Info "Directory exists: $paramSet"
    }
}

# Download function with retry logic
function Download-File {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$Description
    )
    
    if ((Test-Path $OutputPath) -and -not $Force) {
        Write-Warn "  Skipped (exists): $Description"
        return $true
    }
    
    Write-Info "  Downloading: $Description"
    
    $maxRetries = 3
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing -TimeoutSec 60
            Write-Success "  Success: $Description"
            return $true
        }
        catch {
            $retryCount++
            if ($retryCount -eq $maxRetries) {
                Write-Fail "  Failed: $Description - $($_.Exception.Message)"
                return $false
            }
            Write-Warn "  Retry $retryCount/$maxRetries for: $Description"
            Start-Sleep -Seconds 2
        }
    }
    
    return $false
}

# Download NIST ACVP test vectors
Write-Info ""
Write-Info "--- Downloading NIST ACVP Test Vectors ---"

# Note: NIST ACVP Server structure needs to be verified
# The following URLs are examples and may need adjustment based on actual ACVP Server structure

$acvpVectors = @(
    @{
        ParamSet = "ML-KEM-512"
        Files = @(
            @{ Name = "keyGen.json"; Path = "ML-KEM-keyGen-FIPS203/internalProjection.json" },
            @{ Name = "encapDecap.json"; Path = "ML-KEM-encapDecap-FIPS203/internalProjection.json" }
        )
    },
    @{
        ParamSet = "ML-KEM-768"
        Files = @(
            @{ Name = "keyGen.json"; Path = "ML-KEM-keyGen-FIPS203/internalProjection.json" },
            @{ Name = "encapDecap.json"; Path = "ML-KEM-encapDecap-FIPS203/internalProjection.json" }
        )
    },
    @{
        ParamSet = "ML-KEM-1024"
        Files = @(
            @{ Name = "keyGen.json"; Path = "ML-KEM-keyGen-FIPS203/internalProjection.json" },
            @{ Name = "encapDecap.json"; Path = "ML-KEM-encapDecap-FIPS203/internalProjection.json" }
        )
    }
)

$downloadSuccess = $true

foreach ($vectorSet in $acvpVectors) {
    Write-Info ""
    Write-Info "Parameter Set: $($vectorSet.ParamSet)"
    
    foreach ($file in $vectorSet.Files) {
        $url = "$acvpBaseUrl/$($file.Path)"
        $outputPath = Join-Path $PSScriptRoot "$($vectorSet.ParamSet)\$($file.Name)"
        
        $result = Download-File -Url $url -OutputPath $outputPath -Description $file.Name
        if (-not $result) {
            $downloadSuccess = $false
        }
    }
}

# Download BouncyCastle KAT files if available
Write-Info ""
Write-Info "--- Downloading BouncyCastle Known Answer Tests ---"

$bcKatFiles = @(
    @{ ParamSet = "ML-KEM-512"; FileName = "kat.rsp"; BcPath = "kyber/PQCkemKAT_kyber512.rsp" },
    @{ ParamSet = "ML-KEM-768"; FileName = "kat.rsp"; BcPath = "kyber/PQCkemKAT_kyber768.rsp" },
    @{ ParamSet = "ML-KEM-1024"; FileName = "kat.rsp"; BcPath = "kyber/PQCkemKAT_kyber1024.rsp" }
)

foreach ($katFile in $bcKatFiles) {
    $url = "$bcBaseUrl/$($katFile.BcPath)"
    $outputPath = Join-Path $scriptDir "$($katFile.ParamSet)\$($katFile.FileName)"

    $result = Download-File -Url $url -OutputPath $outputPath -Description "$($katFile.ParamSet) KAT"
    if (-not $result) {
        Write-Warn "  Note: BouncyCastle KAT files may use Kyber naming (pre-FIPS 203)"
    }
}

# Summary
Write-Info ""
Write-Info "=== Download Summary ==="

$totalFiles = 0
$existingFiles = 0

foreach ($paramSet in $parameterSets) {
    $dir = Join-Path $scriptDir $paramSet
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue
        $fileCount = ($files | Measure-Object).Count
        $totalFiles += $fileCount

        if ($fileCount -gt 0) {
            $message = "$paramSet - $fileCount file(s)"
            Write-Success $message
            $existingFiles += $fileCount
        } else {
            Write-Warn "$paramSet - No files downloaded"
        }
    } else {
        Write-Warn "$paramSet - Directory not found"
    }
}

Write-Info ""
if ($existingFiles -gt 0) {
    Write-Success "Total test vector files: $existingFiles"
} else {
    Write-Fail "No test vector files were downloaded."
    Write-Info ""
    Write-Info "Note: The NIST ACVP Server URLs may have changed."
    Write-Info "Please check the README.md for updated download instructions."
    Write-Info "You can also manually download from:"
    Write-Info "  - https://github.com/usnistgov/ACVP-Server"
    Write-Info "  - https://github.com/bcgit/bc-csharp/tree/master/crypto/test/data/pqc"
    exit 1
}

Write-Info ""
Write-Info "Use -Force to re-download existing files."
Write-Info ""
Write-Success "Download complete!"
