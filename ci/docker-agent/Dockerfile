
# Docker CLI
FROM docker:27-cli AS dockercli

# Official Jenkins inbound agent with Java 21
FROM jenkins/inbound-agent:jdk21

USER root

# Copy Docker CLI
COPY --from=dockercli \
    /usr/local/bin/docker \
    /usr/local/bin/docker

# Copy tested Trivy binary
COPY trivy /usr/local/bin/trivy

RUN chmod 755 /usr/local/bin/docker \
    /usr/local/bin/trivy \
    && mkdir -p /home/jenkins/agent \
    && chown jenkins:jenkins /home/jenkins/agent

USER jenkins

WORKDIR /home/jenkins/agent
