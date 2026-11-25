pipeline {
  agent { label 'built-in' }
  options { timestamps(); disableConcurrentBuilds(); buildDiscarder(logRotator(numToKeepStr: '20')); timeout(time: 45, unit: 'MINUTES') }
  tools { jdk 'jdk21'; maven 'maven3' }
  environment {
    TRIVY = '/usr/local/bin/trivy'
    TRIVY_CACHE_DIR = '/var/jenkins_home/.cache/trivy'
    // Stable lab contract identifiers, NOT claims of a certified SLSA builder.
    // Keep these independent of the application's Git repository URL.
    PROVENANCE_BUILD_TYPE = 'urn:banking-cicd:buildtype:jenkins-docker:v1'
    PROVENANCE_BUILDER_ID = 'urn:banking-cicd:builder:jenkins-local:v1'
    // Source host allowlist for this lab. Set to an approved SCM host for other projects.
    PROVENANCE_ALLOWED_SCM_HOST = 'github.com'
  }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Tool Preflight') {
      steps { sh '''
        java -version; mvn -version; git --version
        test -x "$TRIVY" || { echo 'Trivy not installed: see ci/install-trivy.ps1'; exit 2; }
        "$TRIVY" --version
      ''' }
    }
    stage('Compile & Unit Tests') {
      steps { sh 'mvn -B -ntp clean verify' }
    }

	stage('SonarQube Analysis') {
		steps {
			withSonarQubeEnv(
				installationName: 'banking-sonarqube',
				credentialsId: 'sonarqube-token'
			) {
				sh '''
					set -eu

					# Supplied securely by the SonarQube Jenkins plugin
					test -n "${SONAR_AUTH_TOKEN:-}"

					export SONAR_TOKEN="$SONAR_AUTH_TOKEN"

					mvn -B -ntp \
					  org.sonarsource.scanner.maven:sonar-maven-plugin:5.1.0.4751:sonar \
					  -Dsonar.projectKey=banking-api \
					  -Dsonar.projectName=banking-api
				'''
			}
		}
	}

    stage('SonarQube Quality Gate') {
      steps { timeout(time: 10, unit: 'MINUTES') { waitForQualityGate abortPipeline: true } }
    }


	stage('Trivy Vulnerability Gate') {
		steps {
			sh '''
				set -eu

				mkdir -p reports
				rm -f reports/trivy-vulnerabilities.json

				"$TRIVY" fs \
				  --scanners vuln \
				  --severity HIGH,CRITICAL \
				  --format json \
				  --exit-code 0 \
				  --no-progress \
				  --cache-dir "$TRIVY_CACHE_DIR" \
				  --output reports/trivy-vulnerabilities.json \
				  .
			'''

			script {
				def report = readJSON(
					file: 'reports/trivy-vulnerabilities.json',
					returnPojo: true
				)

				if (report.Results == null) {
					error('Invalid Trivy report: Results missing')
				}

				int critical = 0
				int high = 0

				report.Results.each { result ->
					(result.Vulnerabilities ?: []).each { vuln ->
						if (vuln.Severity == 'CRITICAL') {
							critical++
						} else if (vuln.Severity == 'HIGH') {
							high++
						}
					}
				}

				echo "TRIVY CRITICAL: ${critical}"
				echo "TRIVY HIGH: ${high}"

				if (critical + high > 0) {
					unstable(
						"TRIVY SECURITY GATE: " +
						"${critical + high} vulnerabilities detected"
					)
				} else {
					echo 'TRIVY VULNERABILITY GATE PASSED'
				}
			}
		}
	}


    stage('Trivy Secret Gate') {
      steps { sh '''
        "$TRIVY" fs --scanners secret --exit-code 1 --no-progress \
          --cache-dir "$TRIVY_CACHE_DIR" .
      ''' }
    }

	stage('Docker Image Security Gate') {
		agent {
			label 'docker-build'
		}

		steps {
			checkout scm

			sh '''
				set -eu

				IMAGE_TAG="banking-api:ci-${BUILD_NUMBER}"

				mkdir -p reports
				rm -f reports/trivy-image.json

				echo "Building Docker image: $IMAGE_TAG"

				docker build --pull \
				  -t "$IMAGE_TAG" .

				docker image inspect \
				  --format '{{.Id}}' "$IMAGE_TAG" \
				  > reports/docker-image-id.txt

				docker save \
				  -o banking-api-image.tar \
				  "$IMAGE_TAG"

				trivy image \
				  --input banking-api-image.tar \
				  --scanners vuln \
				  --severity HIGH,CRITICAL \
				  --format json \
				  --exit-code 0 \
				  --no-progress \
				  --cache-dir /home/jenkins/.cache/trivy \
				  --output reports/trivy-image.json
			'''

			script {
				def report = readJSON(
					file: 'reports/trivy-image.json',
					returnPojo: true
				)

				if (report.Results == null) {
					error('Invalid Trivy image report')
				}

				int critical = 0
				int high = 0

				report.Results.each { result ->
					(result.Vulnerabilities ?: []).each { vuln ->
						if (vuln.Severity == 'CRITICAL') {
							critical++
						} else if (vuln.Severity == 'HIGH') {
							high++
						}
					}
				}

				echo "IMAGE CRITICAL: ${critical}"
				echo "IMAGE HIGH: ${high}"

				if (critical + high > 0) {
					unstable(
						"Docker image contains " +
						"${critical + high} HIGH/CRITICAL findings"
					)
				} else {
					echo 'DOCKER IMAGE SECURITY GATE PASSED'
				}
			}
			
			
			sh '''
				set -eu

				echo "Generating CycloneDX SBOM..."
				rm -f reports/sbom.cdx.json
				test -s banking-api-image.tar
				mkdir -p reports

				trivy image \
				  --input banking-api-image.tar \
				  --format cyclonedx \
				  --scanners vuln \
				  --no-progress \
				  --cache-dir /home/jenkins/.cache/trivy \
				  --output reports/sbom.cdx.json

				test -s reports/sbom.cdx.json

				echo "SBOM GENERATED"
			'''

			script {
				def sbom = readJSON(
					file: 'reports/sbom.cdx.json',
					returnPojo: true
				)

				if (sbom.bomFormat != 'CycloneDX') {
					error('SBOM VALIDATION FAILED: Invalid format')
				}

				def components = sbom.components ?: []

				if (components.isEmpty()) {
					error('SBOM VALIDATION FAILED: No components detected')
				}

				echo "SBOM FORMAT: ${sbom.bomFormat}"
				echo "SBOM VERSION: ${sbom.specVersion}"
				echo "SBOM COMPONENTS: ${components.size()}"
				echo "SBOM VALIDATION PASSED"
			}

			// E01: preserve exact SBOM produced by the approved Docker image build.
			stash(name: 'release-sbom', includes: 'reports/sbom.cdx.json')

		}

		post {
			always {
				archiveArtifacts(
					artifacts: 'reports/trivy-image.json,reports/docker-image-id.txt,reports/sbom.cdx.json',
					allowEmptyArchive: true,
					fingerprint: true
				)

				sh 'rm -f banking-api-image.tar'
			}
		}
	}

    stage('Artifact Evidence') {
      steps {
        sh 'sha256sum target/*.jar > target/SHA256SUMS.txt'
        archiveArtifacts artifacts: 'target/*.jar,target/SHA256SUMS.txt', fingerprint: true
      }
    }
	
	stage('Final Security Gate') {
		steps {
			script {
				if (currentBuild.currentResult == 'UNSTABLE') {
					error(
						'SECURITY GATE FAILED: ' +
						'Build contains unresolved security findings'
					)
				}

				echo 'FINAL SECURITY GATE PASSED'
			}
		}
	}
	
	stage('Registry Publish') {
		agent {
			label 'docker-build'
		}

		when {
			beforeAgent true
			expression {
				return currentBuild.currentResult == 'SUCCESS'
			}
		}

		steps {
			sh '''
				set -eu

				IMAGE_LOCAL="banking-api:ci-${BUILD_NUMBER}"
				IMAGE_REGISTRY="localhost:5000/banking-api:ci-${BUILD_NUMBER}"

				mkdir -p reports

				echo "Checking approved image..."

				docker image inspect "$IMAGE_LOCAL" \
				  --format '{{.Id}}' \
				  > reports/image-id-before-push.txt

				echo "Tagging the approved image..."

				docker tag "$IMAGE_LOCAL" "$IMAGE_REGISTRY"

				echo "Publishing image to registry..."

				docker push "$IMAGE_REGISTRY"

				echo "Verifying pushed image..."

				docker pull "$IMAGE_REGISTRY"

				docker image inspect "$IMAGE_REGISTRY" \
				  --format '{{.Id}}' \
				  > reports/image-id-after-push.txt

				cmp \
				  reports/image-id-before-push.txt \
				  reports/image-id-after-push.txt

				docker image inspect "$IMAGE_REGISTRY" \
				  --format '{{index .RepoDigests 0}}' \
				  | sed 's#^banking-api@#localhost:5000/banking-api@#' \
				  > reports/published-image-digest.txt
				  
				sed -i 's#^localhost:5000/#ci-registry-1:5000/#' \
					reports/published-image-digest.txt

				cat reports/published-image-digest.txt

				test -s reports/published-image-digest.txt

				echo "REGISTRY PUBLISH PASSED"

			'''
			
			stash(
				name: 'approved-image',
				includes: 'reports/published-image-digest.txt'
			)

			script {
				def imageRef = readFile(
					'reports/published-image-digest.txt'
				).trim()
				def prefix = 'ci-registry-1:5000/banking-api@sha256:'
				if (!imageRef.startsWith(prefix) ||
					!(imageRef.substring(prefix.length()) ==~ /[0-9a-f]{64}/)) {
					error('Invalid published image reference')
				} 	

				def gitSha = sh(
					script: 'git rev-parse HEAD',
					returnStdout: true
				).trim()

				def imageId = readFile(
					'reports/image-id-before-push.txt'
				).trim()

				def manifest = [
					schemaVersion : '1.0',
					application   : 'banking-api',
					environment   : 'banking-dev',
					sourceCommit  : gitSha,
					jenkinsJob    : env.JOB_NAME,
					jenkinsBuild  : env.BUILD_NUMBER,
					buildUrl      : env.BUILD_URL,
					imageReference: imageRef,
					imageId       : imageId,
					sbom          : 'reports/sbom.cdx.json',
					securityReport: 'reports/trivy-image.json'
				]

				writeJSON(
					file: 'reports/release-manifest.json',
					json: manifest,
					pretty: 4
				)

				echo "RELEASE MANIFEST GENERATED"
			}
			
		}

		post {
			always {
				archiveArtifacts(
					artifacts: 'reports/published-image-digest.txt,reports/release-manifest.json,reports/image-id-*.txt',
					allowEmptyArchive: true,
					fingerprint: true
				)
			}
		}
	}
	
	stage('Image Signing') {
		agent {
			label 'docker-build'
		}

		when {
			beforeAgent true
			expression {
				currentBuild.currentResult == 'SUCCESS'
			}
		}

		steps {
			unstash 'approved-image'

			withEnv([
				'PATH+COSIGN=/home/jenkins/agent/bin'
			]) {
				withCredentials([
					file(
						credentialsId: 'banking-cosign-private-key',
						variable: 'COSIGN_KEY_FILE'
					),
					string(
						credentialsId: 'banking-cosign-password',
						variable: 'COSIGN_PASSWORD'
					)
				]) {
					sh '''
						set -eu
						set +x

						IMAGE_REF="$(cat reports/published-image-digest.txt)"

						echo "Signing approved image: $IMAGE_REF"

						# Docker daemon and Jenkins agent have
						# different network namespaces.
						# Access registry directly via Docker DNS.

						SIGN_REF="$IMAGE_REF"

						cosign sign \
						  --key "$COSIGN_KEY_FILE" \
						  --allow-http-registry \
						  --tlog-upload=false \
						  --use-signing-config=false \
						  --new-bundle-format=false \
						  --registry-referrers-mode=legacy \
						  --yes \
						  "$SIGN_REF"

						echo "IMAGE SIGNING PASSED"
					'''
				}
			}
		}
	}

	stage('Image Signature Verification') {
		agent {
			label 'docker-build'
		}

		steps {
			unstash 'approved-image'

			withEnv([
				'PATH+COSIGN=/home/jenkins/agent/bin'
			]) {
				withCredentials([
					file(
						credentialsId: 'banking-cosign-public-key',
						variable: 'COSIGN_PUBLIC_KEY'
					)
				]) {
					sh '''
						set -eu
						set +x

						mkdir -p reports

						rm -f reports/cosign-verification.json
						rm -f reports/signature-verified-image.txt

						IMAGE_REF="$(cat reports/published-image-digest.txt)"


						VERIFY_REF="$IMAGE_REF"

						echo "Verifying image: $IMAGE_REF"

						cosign verify \
						  --key "$COSIGN_PUBLIC_KEY" \
						  --allow-http-registry \
						  --insecure-ignore-tlog=true \
						  "$VERIFY_REF" \
						  > reports/cosign-verification.json

						test -s reports/cosign-verification.json

						printf '%s\\n' "$IMAGE_REF" \
						  > reports/signature-verified-image.txt

						echo "IMAGE SIGNATURE VERIFICATION PASSED"
					'''
				}
			}

			stash(
				name: 'verified-image',
				includes: 'reports/signature-verified-image.txt'
			)
		}

		post {
			always {
				archiveArtifacts(
					artifacts: 'reports/cosign-verification.json,reports/signature-verified-image.txt',
					fingerprint: true,
					allowEmptyArchive: true
				)
			}
		}
	}


	// CD-02.4E E02 — self-reported provenance derived from this exact build.
	stage('Release Provenance Generation') {
		agent { label 'docker-build' }
		steps {
			checkout scm
			unstash 'approved-image'
			unstash 'release-sbom'
			script {
				def imageRef = readFile('reports/published-image-digest.txt').trim()
				// Do not retain java.util.regex.Matcher across Jenkins CPS suspension points.
				if (!(imageRef ==~ /^ci-registry-1:5000\/banking-api@sha256:[0-9a-f]{64}$/)) {
					error('PROVENANCE FAILED: unexpected image reference')
				}
				def gitSha = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
				if (!(gitSha ==~ /[0-9a-f]{40}/)) { error('PROVENANCE FAILED: invalid Git SHA') }
				def sbom = readJSON(file: 'reports/sbom.cdx.json', returnPojo: true)
				if (sbom.bomFormat != 'CycloneDX' || !(sbom.components instanceof List) || sbom.components.isEmpty()) {
					error('PROVENANCE FAILED: invalid or empty CycloneDX SBOM')
				}
				// SCM is evidence from the checked-out commit, not a hardcoded GitHub URL.
				// Capture in the same agent/workspace as gitSha to avoid cross-agent drift.
				def repo = sh(script: 'git config --get remote.origin.url', returnStdout: true).trim()
				if (!repo) { error('PROVENANCE FAILED: missing origin URL') }
				// Normalize common Git SSH syntax; never include userinfo/password in provenance.
				if (repo.startsWith('git@')) {
					repo = repo.replaceFirst(/^git@([^:]+):/, 'https://$1/')
				}
				if (!(repo ==~ /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9._~\/-]+(?:\.git)?$/)) {
					error('PROVENANCE FAILED: unsupported SCM URL or embedded credentials')
				}
				// Jenkins Groovy sandbox rejects new java.net.URI(String).
				// Previous regex has already validated an HTTPS URL without userinfo/port.
				// Require the host followed by '/', preventing github.com.evil.example bypass.
				def approvedHost = (env.PROVENANCE_ALLOWED_SCM_HOST ?: '').trim().toLowerCase()
				if (!(approvedHost ==~ /[a-z0-9.-]+/) ||
				    !repo.toLowerCase().startsWith("https://${approvedHost}/")) {
					error('PROVENANCE FAILED: Git remote is not on the approved SCM host')
				}
				def predicate = [
					buildDefinition: [
						buildType: env.PROVENANCE_BUILD_TYPE,
						externalParameters: [repository: repo, revision: gitSha, job: env.JOB_NAME],
						internalParameters: [:],
						resolvedDependencies: [[
							uri: "git+${repo}", digest: [gitCommit: gitSha]
						]]
					],
					runDetails: [
						builder: [id: env.PROVENANCE_BUILDER_ID],
						metadata: [invocationId: "${env.JOB_NAME}/${env.BUILD_NUMBER}"]
					]
				]
				// Builder ID is a locally declared identity, NOT externally verified.
				writeJSON(file: 'reports/slsa-provenance-predicate.json', json: predicate, pretty: 4)
				writeJSON(file: 'reports/attestation-expectations.json', json: [
					imageReference: imageRef,
					gitCommit: gitSha,
					repository: repo,
					invocationId: "${env.JOB_NAME}/${env.BUILD_NUMBER}",
					sbomComponentCount: sbom.components.size()
				], pretty: 4)
				echo "RELEASE PROVENANCE GENERATED (build ${env.BUILD_NUMBER})"
			}
			stash(name: 'release-provenance', includes: 'reports/slsa-provenance-predicate.json,reports/attestation-expectations.json')
		}
		post {
			always {
				archiveArtifacts(artifacts: 'reports/slsa-provenance-predicate.json,reports/attestation-expectations.json', allowEmptyArchive: true, fingerprint: true)
			}
		}
	}

	// CD-02.4E E03 — cosign attest uses OCI format available in this agent.
	// Do NOT copy legacy cosign sign-only flags into cosign attest.
	stage('Release Attestation Signing') {
		agent { label 'docker-build' }
		steps {
			unstash 'approved-image'
			unstash 'release-provenance'
			unstash 'release-sbom'
			withEnv(['PATH+COSIGN=/home/jenkins/agent/bin']) {
				withCredentials([
					file(credentialsId: 'banking-cosign-private-key', variable: 'COSIGN_KEY_FILE'),
					string(credentialsId: 'banking-cosign-password', variable: 'COSIGN_PASSWORD')
				]) {
					sh '''
						set -eu
						set +x
						IMAGE_REF="$(cat reports/published-image-digest.txt)"
						case "$IMAGE_REF" in ci-registry-1:5000/banking-api@sha256:*) ;; *) exit 2 ;; esac
						test -s reports/slsa-provenance-predicate.json
						test -s reports/sbom.cdx.json
						cosign attest --key "$COSIGN_KEY_FILE" \
						  --predicate reports/slsa-provenance-predicate.json \
						  --type slsaprovenance1 --allow-http-registry --yes "$IMAGE_REF"
						echo 'PROVENANCE ATTESTATION SIGNED'
						cosign attest --key "$COSIGN_KEY_FILE" \
						  --predicate reports/sbom.cdx.json \
						  --type cyclonedx --allow-http-registry --yes "$IMAGE_REF"
						echo 'SBOM ATTESTATION SIGNED'
					'''
				}
			}
		}
	}

	// CD-02.4E E04 — first verify cryptographic signatures, then verify claims.
	stage('Release Attestation Verification') {
		agent { label 'docker-build' }
		steps {
			unstash 'approved-image'
			unstash 'release-provenance'
			unstash 'release-sbom'
			withEnv(['PATH+COSIGN=/home/jenkins/agent/bin']) {
				withCredentials([
					file(credentialsId: 'banking-cosign-public-key', variable: 'COSIGN_PUBLIC_KEY')
				]) {
					sh '''
						set -eu
						set +x
						IMAGE_REF="$(cat reports/published-image-digest.txt)"
						mkdir -p reports
						# Local HTTP registry, no transparency-log verification: LAB ONLY.
						cosign verify-attestation --key "$COSIGN_PUBLIC_KEY" \
						  --type slsaprovenance1 --allow-http-registry \
						  --insecure-ignore-tlog=true "$IMAGE_REF" \
						  > reports/verified-provenance.json
						cosign verify-attestation --key "$COSIGN_PUBLIC_KEY" \
						  --type cyclonedx --allow-http-registry \
						  --insecure-ignore-tlog=true "$IMAGE_REF" \
						  > reports/verified-sbom.json
						test -s reports/verified-provenance.json
						test -s reports/verified-sbom.json
						echo 'ATTESTATION CRYPTOGRAPHIC VERIFICATION PASSED'
					'''
				}
			}
			script {
				def expectations = readJSON(file: 'reports/attestation-expectations.json', returnPojo: true)
				def approvedImage = readFile('reports/published-image-digest.txt').trim()
				if (expectations.imageReference != approvedImage) { error('ATTESTATION: image-reference mismatch') }
				// Boolean full-match avoids a non-serializable Matcher in CPS locals.
				if (!(approvedImage ==~ /^ci-registry-1:5000\/banking-api@sha256:[0-9a-f]{64}$/)) {
					error('ATTESTATION: malformed release digest')
				}
				def expectedDigest = approvedImage.substring(approvedImage.lastIndexOf('sha256:') + 7)
				def originalPredicate = readJSON(file: 'reports/slsa-provenance-predicate.json', returnPojo: true)
				def originalSbom = readJSON(file: 'reports/sbom.cdx.json', returnPojo: true)

				// Cosign can return one JSON DSSE envelope PER LINE (NDJSON).
				// The same immutable digest may have attestations from earlier Jenkins builds.
				// Require at least one verified envelope matching THIS build's predicate/SBOM.
				['provenance': 'reports/verified-provenance.json',
				 'sbom': 'reports/verified-sbom.json'].each { kind, file ->
					def lines = readFile(file).readLines().findAll { it.trim() }
					if (lines.isEmpty()) { error("ATTESTATION: no verified envelopes (${kind})") }
					boolean foundCurrentRelease = false
					lines.each { line ->
						def envelope = readJSON(text: line, returnPojo: true)
						if (!(envelope instanceof Map) || !envelope.payload ||
							!(envelope.signatures instanceof List) || envelope.signatures.isEmpty()) {
							error("ATTESTATION: malformed verified DSSE envelope (${kind})")
						}
						def statementText = new String(java.util.Base64.getDecoder().decode(envelope.payload), 'UTF-8')
						def statement = readJSON(text: statementText, returnPojo: true)
						boolean validStatement = statement._type in [
							'https://in-toto.io/Statement/v0.1',
							'https://in-toto.io/Statement/v1'
						]
						boolean validSubject = statement.subject instanceof List &&
							statement.subject.size() == 1 &&
							statement.subject[0].digest?.sha256 == expectedDigest &&
							statement.subject[0].name in [
								'ci-registry-1:5000/banking-api',
								'localhost:5000/banking-api'
							]
						if (validStatement && validSubject) {
							if (kind == 'provenance') {
								if (statement.predicateType == 'https://slsa.dev/provenance/v1' &&
									statement.predicate == originalPredicate &&
									statement.predicate.buildDefinition.externalParameters.revision == expectations.gitCommit &&
									statement.predicate.buildDefinition.externalParameters.repository == expectations.repository &&
									statement.predicate.runDetails.metadata.invocationId == expectations.invocationId) {
									foundCurrentRelease = true
								}
							} else {
								if (statement.predicateType == 'https://cyclonedx.org/bom' &&
									statement.predicate == originalSbom &&
									statement.predicate.bomFormat == 'CycloneDX' &&
									statement.predicate.components instanceof List &&
									statement.predicate.components.size() == expectations.sbomComponentCount) {
									foundCurrentRelease = true
								}
							}
						}
					}
					if (!foundCurrentRelease) {
						error("ATTESTATION: no matching verified attestation for current build (${kind})")
					}
				}

				writeFile(file: 'reports/attestation-verified-image.txt', text: "${approvedImage}\n")
				echo 'RELEASE ATTESTATION SEMANTIC VERIFICATION PASSED'
			}
			stash(name: 'attestation-verified-image', includes: 'reports/attestation-verified-image.txt')
		}
		post {
			always {
				archiveArtifacts(artifacts: 'reports/verified-provenance.json,reports/verified-sbom.json,reports/attestation-verified-image.txt', allowEmptyArchive: true, fingerprint: true)
			}
		}
	}

	// CD-03.2-E — CI-only verified release handoff; NO kubectl, kubeconfig or Argo sync.
	stage('GitOps Release Handoff') {
		agent { label 'docker-build' }
		steps {
			unstash 'approved-image'
			unstash 'verified-image'
			unstash 'attestation-verified-image'
			unstash 'release-provenance'
			script {
				def approved = readFile('reports/published-image-digest.txt').trim()
				def signed = readFile('reports/signature-verified-image.txt').trim()
				def attested = readFile('reports/attestation-verified-image.txt').trim()
				if (!(approved ==~ /^ci-registry-1:5000\/banking-api@sha256:[0-9a-f]{64}$/)) {
					error('HANDOFF FAILED: invalid immutable image digest reference')
				}
				if (approved != signed || approved != attested) {
					error('HANDOFF FAILED: signed/attested digest mismatch')
				}
				def expectations = readJSON(file: 'reports/attestation-expectations.json', returnPojo: true)
				if (expectations.imageReference != approved ||
					expectations.invocationId != "${env.JOB_NAME}/${env.BUILD_NUMBER}") {
					error('HANDOFF FAILED: release identity mismatch')
				}
				def release = [
					schemaVersion: 'banking.gitops.release-handoff/v1',
					status: 'VERIFIED_PENDING_GITOPS_PROMOTION',
					image: approved,
					gitCommit: expectations.gitCommit,
					repository: expectations.repository,
					invocationId: expectations.invocationId,
					application: 'banking-api-dev',
					namespace: 'banking-dev',
					gitopsPath: 'gitops/apps/banking-api/overlays/dev',
					requiresReview: true,
					requiresArgoManualSync: true
				]
				writeJSON(file: 'reports/gitops-release-handoff.json', json: release, pretty: 4)
				echo 'GITOPS RELEASE HANDOFF GENERATED — NO DEPLOYMENT PERFORMED'
			}
		}
		post {
			always {
				archiveArtifacts(artifacts: 'reports/gitops-release-handoff.json', allowEmptyArchive: true, fingerprint: true)
			}
		}
	}


  }
  post {
    always { 
        junit allowEmptyResults: false, testResults: 'target/surefire-reports/*.xml' 
        
        archiveArtifacts(
            artifacts: 'reports/*.json',
            allowEmptyArchive: true,
            fingerprint: true
        )
    }
    success { echo 'CI-ONLY security gates passed; GitOps release handoff archived. No kubectl deployment.' }
    failure { echo 'CI-ONLY failed: inspect first failing stage and scanner report.' }
  }
}
