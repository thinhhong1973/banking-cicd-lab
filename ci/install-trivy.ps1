param(
  [string]$Container = 'banking-jenkins',
  [string]$Version = '0.69.1'
)
$ErrorActionPreference = 'Stop'
$arch = '64bit'
$base = "https://github.com/aquasecurity/trivy/releases/download/v$Version"
$archive = "trivy_${Version}_Linux-${arch}.tar.gz"
$work = Join-Path $env:TEMP "trivy-install-$Version"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Invoke-WebRequest "$base/$archive" -OutFile "$work/$archive"
Invoke-WebRequest "$base/trivy_${Version}_checksums.txt" -OutFile "$work/checksums.txt"
$expected = (Get-Content "$work/checksums.txt" | Where-Object { $_ -match "\s\*?$([regex]::Escape($archive))$" } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
if (-not $expected) { throw 'Checksum entry not found; installation aborted.' }
$actual = (Get-FileHash "$work/$archive" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected.ToLowerInvariant()) { throw 'SHA256 mismatch; installation aborted.' }
tar -xzf "$work/$archive" -C $work trivy
if ($LASTEXITCODE -ne 0) { throw 'Extraction failed.' }
docker exec $Container mkdir -p /var/jenkins_home/tools/trivy
if ($LASTEXITCODE -ne 0) { throw 'Cannot create persistent Jenkins tool directory.' }
docker cp "$work/trivy" "${Container}:/var/jenkins_home/tools/trivy/trivy"
if ($LASTEXITCODE -ne 0) { throw 'docker cp failed.' }
docker exec $Container chmod +x /var/jenkins_home/tools/trivy/trivy
docker exec $Container /var/jenkins_home/tools/trivy/trivy --version
Write-Host 'Trivy installed in Jenkins persistent home; no container rebuild required.'
