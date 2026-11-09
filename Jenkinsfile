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
		}

		post {
			always {
				archiveArtifacts(
					artifacts: 'reports/trivy-image.json,reports/docker-image-id.txt',
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
