# CI.2 Negative Tests (controlled lab only)

## A — SonarQube gate failure (deterministic gate plumbing test)
1. After the initial scan, in SonarQube: Quality Gates > Create `banking-lab-strict`.
2. Add condition **Overall Coverage < 100%** (if available in installed edition; otherwise set **New Code Coverage < 100%** after configuring New Code definition and adding new untested lines).
3. Assign this gate to project `banking-api`.
4. Run Jenkins **Build Now**. Expected: SonarQube Quality Gate stage aborts; no Artifact Evidence stage.
5. Restore original gate assignment. Rerun; confirm gate returns OK.
6. If project has 100% coverage, add an untested Java class/method before step 4. Do not leave intentionally bad code on main.

## B — Trivy CVE detection (isolated test branch)
1. Create branch `lab/negative-trivy` from main.
2. Add a deliberately vulnerable **test-only** Maven dependency `org.apache.logging.log4j:log4j-core:2.14.1` (Log4Shell CVE) to pom.xml, run Maven verify. This is for scanning ONLY: do not run this artifact or deploy it.
3. Run `trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .` from the repository root; expect exit 1 and a CVE finding (scanner database/network required).
4. Remove dependency, rerun Maven and Trivy; confirm no matching finding.
5. Do not merge the vulnerable branch.

## C — Secret detection (isolated branch)
1. In a test branch only, create `ci2-secret-fixture.txt` with a **fake** AWS-style access key string, e.g. `AKIAIOSFODNN7EXAMPLE`. Never use a real key.
2. Run `trivy fs --scanners secret --exit-code 1 .`; expect detection if the scanner rules match the fixture. A fake key may not trigger all scanner versions: check scanner output; use Trivy's documented secret test fixtures if needed.
3. Delete fixture, rerun. Do not push real credentials.

## Interpretation
- `waitForQualityGate` requires Jenkins SonarQube plugin, correct webhook, and Jenkins reachable from SonarQube.
- Scanner failures caused by unavailable databases are infrastructure failures, not evidence of a clean scan. Do not use `|| true` or `allowEmptyResults` to hide them.
- Some Trivy versions need dependency lockfiles, JARs or Maven resolution metadata to discover Java vulnerabilities. Build before scan and inspect findings.
