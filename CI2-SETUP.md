# CI.2 setup — Windows 11 + existing Jenkins Docker

## 0. Preserve existing Jenkins
Do **not** run `docker compose down -v`, do not replace the Jenkins service, and do not delete its named volume. Existing `ci/docker-compose.yml` is unchanged from CI.1.

## 1. SonarQube (separate Docker Compose stack)
```powershell
docker compose -f ci/sonarqube/docker-compose.yml up -d
docker logs -f banking-sonarqube
```
Open http://localhost:9000. Initial credentials for a new local SonarQube Community instance are commonly `admin` / `admin`; change password when prompted. Create project `banking-api` and generate a project analysis token. Never commit the token.

## 2. Jenkins integration
- Jenkins > Manage Jenkins > Plugins: install **SonarQube Scanner for Jenkins** (and its dependencies); restart Jenkins safely if requested.
- Jenkins > Manage Jenkins > Credentials > System > Global credentials > Add Credentials: **Secret text**, paste SonarQube token, ID `sonarqube-token`.
- Jenkins > Manage Jenkins > System > SonarQube servers: Name `banking-sonarqube`, Server URL `http://host.docker.internal:9000`, Server authentication token `sonarqube-token`.
- SonarQube > Administration > Configuration > Webhooks: URL `http://host.docker.internal:8085/sonarqube-webhook/` (the final slash matters). Use this for Docker Desktop Windows; verify reachability from the SonarQube container. In production use an authenticated/internal endpoint and restricted networking.
- For the initial lab, use an unprotected webhook (no shared webhook secret) only on a trusted local environment; add a webhook secret and Jenkins validation in hardened deployments.
- Quality Gates: assign a gate to `banking-api` (default Sonar way is a good baseline); CI will wait for status.

## 3. Install Trivy inside existing Jenkins container (persistent volume)
```powershell
# Find actual container name:
docker ps --format 'table {{.Names}}	{{.Ports}}'
# Replace banking-jenkins if different:
.\ci\install-trivy.ps1 -Container banking-jenkins
```
The script downloads a pinned Linux x86_64 Trivy binary, verifies its SHA256 against the upstream checksums file, and copies it into `/var/jenkins_home/tools/trivy/trivy`. It does NOT change the Jenkins image. This path persists across container recreation **if the existing Jenkins home volume is retained**. On ARM64 hosts, use an ARM64 release instead.

## 4. Validate network and tools
```powershell
docker exec banking-jenkins sh -c 'java -version; mvn -version; /var/jenkins_home/tools/trivy/trivy --version'
docker exec banking-jenkins sh -c 'curl -fsS http://host.docker.internal:9000/api/system/status || true'
```
If curl is missing, use `wget` or test connectivity with Java. `host.docker.internal` is the Docker Desktop host gateway, not localhost inside a container.

## 5. Push code
```powershell
git status
git add Jenkinsfile .gitignore CI2-SETUP.md ci/install-trivy.ps1 ci/sonarqube/docker-compose.yml ci/negative-tests.md
git commit -m 'CI2: SonarQube and Trivy quality gates'
git push origin main
```
**Before git add:** remove sensitive `jenkin-pass.txt` from tracking and rotate any real exposed password. Deleting a tracked file does not erase Git history.

## 6. Run Jenkins
Existing Pipeline job `banking-api-ci` > Build Now. Expect `Tool Preflight`, `Compile & Unit Tests`, `SonarQube Analysis`, `SonarQube Quality Gate`, `Trivy Vulnerability Gate`, `Trivy Secret Gate`, `Artifact Evidence`.

## 7. Negative tests
See `ci/negative-tests.md`. Test gate failures on a branch or disposable lab project; restore original gate and confirm green pipeline. Never deploy vulnerable test fixtures.

## Troubleshooting
- `Tool type jdk does not have install`: keep existing `jdk21` and `maven3` Jenkins tool definitions from CI.1.
- Sonar analysis 401: project token missing/invalid or server config wrong.
- Sonar analysis `Connection refused`: from Jenkins container, `localhost:9000` is NOT SonarQube; use `host.docker.internal:9000`.
- Quality Gate times out: inspect SonarQube webhook deliveries, plugin, `/sonarqube-webhook/` path and Jenkins accessibility.
- Trivy scan errors: verify vulnerability DB access; do not convert scanner error into PASS.
- Trivy reports existing HIGH/CRITICAL CVEs: this is an expected valid gate failure, not a Jenkins defect. Remediate dependencies/base image or use documented time-limited exception processes.
- Local SonarQube is a lab instance, not production HA; consider PostgreSQL, supported runtime sizing, backups and hardening for real deployments.
