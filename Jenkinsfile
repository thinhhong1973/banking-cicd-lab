pipeline {
  agent { label 'built-in' }
  options { timestamps(); disableConcurrentBuilds(); buildDiscarder(logRotator(numToKeepStr: '20')); timeout(time: 30, unit: 'MINUTES') }
  tools { jdk 'jdk21'; maven 'maven3' }
  environment {
    TRIVY = '/usr/local/bin/trivy'
    TRIVY_CACHE_DIR = '/var/jenkins_home/.cache/trivy'
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

	/*
	stage('Deployment Approval') {
		when {
			expression {
				currentBuild.currentResult == 'SUCCESS'
			}
		}

		steps {
			timeout(time: 10, unit: 'MINUTES') {
				input(
					message: 'Deploy approved Banking API to banking-dev?',
					ok: 'Approve Deployment'
				)
			}
		}
	}
	*/
	
	stage('Kubernetes Deploy & Smoke Test') {
		agent {
			label 'docker-build'
		}
		
		steps {
			withEnv(['PATH+KUBECTL=/home/jenkins/agent/bin']) {

				sh '''
					set -eu

					echo "Checking kubectl..."
					command -v kubectl
					kubectl version --client

					echo "Kubectl ready"
				'''

				unstash 'approved-image'
				
				unstash 'verified-image'

				withCredentials([
					file(
						credentialsId: 'banking-dev-kubeconfig',
						variable: 'KUBECONFIG'
					)
				]) {
				
					sh '''
						set -eu
						set +x

						echo "Checking Kubernetes authentication..."

						kubectl -n banking-dev get deployment banking-api

						echo "Checking deployment permission..."

						kubectl auth can-i patch deployment/banking-api \
						  -n banking-dev

						echo "KUBERNETES AUTHENTICATION PASSED"
					'''
		
					sh '''
						set -eu
						set +x
						
						echo "Checking Kubernetes RBAC..."

						test "$(kubectl auth can-i get deployment/banking-api \
						  -n banking-dev)" = "yes"

						test "$(kubectl auth can-i patch deployment/banking-api \
						  -n banking-dev)" = "yes"

						test "$(kubectl auth can-i list deployments \
						  -n banking-dev)" = "yes"

						echo "KUBERNETES RBAC CHECK PASSED"

						NS="banking-dev"
						DEPLOY="banking-api"
						NEW_IMAGE="$(cat reports/published-image-digest.txt)"
						OLD_IMAGE="$(kubectl -n "$NS" get deployment "$DEPLOY" \
						  -o jsonpath='{.spec.template.spec.containers[0].image}')"

						case "$NEW_IMAGE" in
						  ci-registry-1:5000/banking-api@sha256:*) ;;
						  *) echo "Invalid approved image reference"; exit 1 ;;
						esac

						mkdir -p reports
						printf '%s\\n' "$OLD_IMAGE" \
						  > reports/previous-image.txt
						printf '%s\\n' "$NEW_IMAGE" \
						  > reports/deployed-image.txt

						DEPLOY_STARTED=0
						COMPLETED=0
						PF_PID=""

						cleanup() {
							rc=$?
							trap - EXIT

							if [ -n "$PF_PID" ]; then
								kill "$PF_PID" 2>/dev/null || true
							fi

							if [ "$COMPLETED" -ne 1 ] &&
							   [ "$DEPLOY_STARTED" -eq 1 ]; then
								echo "Deployment failed. Restoring previous image..."

								kubectl -n "$NS" set image \
								  deployment/"$DEPLOY" \
								  banking-api="$OLD_IMAGE" || true

								kubectl -n "$NS" rollout status \
								  deployment/"$DEPLOY" \
								  --timeout=180s || true

								echo "ROLLBACK ATTEMPTED"
								printf '%s\\n' "ROLLBACK_ATTEMPTED" \
								  > reports/deploy-result.txt
							fi

							exit "$rc"
						}

						trap cleanup EXIT

						echo "Previous image: $OLD_IMAGE"
						echo "Approved image: $NEW_IMAGE"

						if [ "$OLD_IMAGE" != "$NEW_IMAGE" ]; then
							test -s reports/signature-verified-image.txt

							cmp reports/published-image-digest.txt \
								reports/signature-verified-image.txt

							echo "VERIFIED RELEASE DIGEST MATCHED"
							kubectl -n "$NS" set image \
							  deployment/"$DEPLOY" \
							  banking-api="$NEW_IMAGE"

							DEPLOY_STARTED=1
						fi

						kubectl -n "$NS" rollout status \
						  deployment/"$DEPLOY" \
						  --timeout=180s

						kubectl -n "$NS" get deployment "$DEPLOY" \
						  -o yaml > reports/deployment-evidence.yaml

						ACTUAL_IMAGE="$(kubectl -n "$NS" get deployment "$DEPLOY" \
						  -o jsonpath='{.spec.template.spec.containers[0].image}')"

						test "$ACTUAL_IMAGE" = "$NEW_IMAGE"

						kubectl -n "$NS" get deployment "$DEPLOY" \
						  -o jsonpath='{.status.readyReplicas}' \
						  > reports/ready-replicas.txt

						test "$(cat reports/ready-replicas.txt)" = "2"

						# Port forward for smoke testing
						kubectl -n "$NS" port-forward \
						  service/banking-api 18080:8080 \
						  > reports/port-forward.log 2>&1 &

						PF_PID=$!

						READY=0
						for i in $(seq 1 30); do
							if curl -fsS \
							  http://127.0.0.1:18080/actuator/health/readiness \
							  > reports/readiness.json 2>/dev/null; then
								READY=1
								break
							fi
							sleep 2
						done

						test "$READY" -eq 1
						grep -q '"status":"UP"' reports/readiness.json

						curl -fsS \
						  http://127.0.0.1:18080/api/v1/accounts/ACC-001/balance \
						  > reports/balance-smoke.json

						grep -q 'VND' reports/balance-smoke.json

						printf '%s\\n' "SUCCESS" \
						  > reports/deploy-result.txt

						COMPLETED=1
						echo "KUBERNETES DEPLOYMENT PASSED"
						echo "REST SMOKE TEST PASSED"
					'''
				}
				
			}
		}

		post {
			always {
				archiveArtifacts(
					artifacts: 'reports/deploy-result.txt,reports/previous-image.txt,reports/deployed-image.txt,reports/deployment-evidence.yaml,reports/ready-replicas.txt,reports/readiness.json,reports/balance-smoke.json,reports/port-forward.log',
					allowEmptyArchive: true,
					fingerprint: true
				)
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
    success { echo 'CI.2 security gates passed; artifacts archived.' }
    failure { echo 'CI.2 failed: inspect first failing stage and scanner report.' }
  }
}
