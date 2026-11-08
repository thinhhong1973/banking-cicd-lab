pipeline {
  agent any
  options { timestamps(); disableConcurrentBuilds(); buildDiscarder(logRotator(numToKeepStr: '20')) }
  tools { jdk 'jdk21'; maven 'maven3' }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Compile') { steps { sh 'mvn -B -ntp -DskipTests compile' } }
    stage('Unit Tests') { steps { sh 'mvn -B -ntp test' } }
    stage('Package') { steps { sh 'mvn -B -ntp -DskipTests package' } }
    stage('Artifact Evidence') { steps { sh 'sha256sum target/*.jar > target/SHA256SUMS.txt' } }
  }
  post {
    always { junit allowEmptyResults: false, testResults: 'target/surefire-reports/*.xml' }
    success { archiveArtifacts artifacts: 'target/*.jar,target/SHA256SUMS.txt', fingerprint: true }
  }
}
