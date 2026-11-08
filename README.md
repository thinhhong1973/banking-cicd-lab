# Banking CI/CD Lab — CI.1

## Prerequisites
- Windows 11, Docker Desktop, Git, JDK 21, Maven 3.9+ (or Maven in Jenkins)
- Git repository reachable from Jenkins (GitHub/GitLab or another remote)

## 1. Local tests
Run at project root:

```powershell
mvn -B clean verify
java -jar target/banking-api-0.1.0.jar
# separate PowerShell window:
Invoke-RestMethod http://localhost:8080/api/v1/accounts/ACC-001/balance
```

## 2. Jenkins
```powershell
docker compose -f ci/docker-compose.yml up -d
docker compose -f ci/docker-compose.yml exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```
Visit http://localhost:8085 and install suggested plugins. In Manage Jenkins > Tools, configure JDK named `jdk21` and Maven named `maven3` (JDK 21 and Maven 3.9+). Jenkins image includes Java 21 but Maven is configured via Tools. Create a Pipeline job, select Pipeline script from SCM, Git, supply your reachable repository URL, branch `*/main`, script path `Jenkinsfile`. Commit and push all files before Build Now.

## 3. Expected outcome
Stages: Checkout, Compile, Unit Tests, Package, Artifact Evidence. Two tests pass; `target/banking-api-0.1.0.jar` and SHA256SUMS archived.

## 4. Security notes
Demo only. Jenkins controller runs builds for simplicity; production uses isolated ephemeral agents, protected credentials, trusted repositories, separate deployment identities and hardened networking. Do not mount Docker socket or give Jenkins cluster-admin permissions. The example API is deliberately unauthenticated; do not expose it to production.

## 5. Next milestones
CI.2 SonarQube + Trivy; CI.3 OCI image signing and registry; CI.4 GitOps and Kubernetes; CI.5 approval, evidence, failure injection.
