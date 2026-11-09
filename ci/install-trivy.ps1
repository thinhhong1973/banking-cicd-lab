
param(
    [string]$Container = "ci-jenkins-1",
    [string]$Version = "0.76.2"
)

$ErrorActionPreference = "Stop"

$work = Join-Path $env:TEMP "trivy-install"
New-Item -ItemType Directory -Force -Path $work | Out-Null

$archive = "trivy_${Version}_Linux-64bit.tar.gz"
$base = "https://github.com/aquasecurity/trivy/releases/download/v$Version"
$url = "$base/$archive"
$file = Join-Path $work $archive

Write-Host "Downloading: $url"

Invoke-WebRequest -Uri $url -OutFile $file

if (-not (Test-Path $file)) {
    throw "Trivy archive download failed"
}

Write-Host "Extracting Trivy..."

tar -xzf $file -C $work trivy

Write-Host "Copying Trivy to Jenkins..."

docker cp (Join-Path $work "trivy") "${Container}:/tmp/trivy"

docker exec -u 0 $Container sh -c "install -m 0755 /tmp/trivy /usr/local/bin/trivy && rm /tmp/trivy"

Write-Host "Verifying installation..."

docker exec $Container trivy --version

Write-Host "Trivy installation completed."
