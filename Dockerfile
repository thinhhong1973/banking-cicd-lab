
# ==========================================
# Stage 1: Maven Build
# ==========================================
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build

COPY pom.xml .
COPY src ./src

RUN mvn -B -ntp clean package -DskipTests


# ==========================================
# Stage 2: Runtime
# ==========================================
FROM eclipse-temurin:21-jre

WORKDIR /app

# Update vulnerable OS packages
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
       apt-get install -y --no-install-recommends \
       --only-upgrade apt libapt-pkg7.0 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root application user
RUN groupadd --system appgroup \
    && useradd --system \
       --gid appgroup \
       --home-dir /app \
       appuser

COPY --from=builder \
    /build/target/banking-api-0.1.0.jar \
    /app/app.jar

RUN chown appuser:appgroup /app/app.jar

USER appuser

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
