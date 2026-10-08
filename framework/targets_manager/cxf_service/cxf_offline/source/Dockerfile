# syntax=docker/dockerfile:1.4
ARG BASE_REGISTRY=docker.1ms.run

# Stage 1 — Maven builder
# Changed from `maven:3.9-eclipse-temurin-11` which docker.1ms.run has paywalled.
# The unversioned `maven:3-eclipse-temurin-11` alias stays on free tier and
# resolves to the current 3.x.x release; functionally identical for our
# `mvn package` workflow.
FROM ${BASE_REGISTRY}/library/maven:3-eclipse-temurin-11 AS build
WORKDIR /src

# Ship the mirror config into the builder so plugin + central downloads
# go through Aliyun (avoids Maven Central from Docker Hub's POV).
COPY settings-docker.xml /root/.m2/settings.xml

COPY pom.xml .
# Do NOT use "|| true" here — a silent dependency-resolution failure at
# this point produces a WAR that is missing JARs but still packages
# successfully on the next `mvn package`, causing Tomcat to accept the
# WAR with no ApplicationContext and return 404 on every request.
# Fail loudly on bad poms instead of cascading to a silent 404 loop.
RUN --mount=type=cache,target=/root/.m2/repository \
    mvn -q -B -U -s /root/.m2/settings.xml dependency:go-offline

COPY src ./src
RUN --mount=type=cache,target=/root/.m2/repository \
    mvn -q -B -s /root/.m2/settings.xml package -DskipTests

# Stage 2 — Tomcat runtime
# Changed from `tomcat:9-jre11` (paywalled).  `9-jdk11-temurin` ships a
# JDK instead of a JRE but is otherwise identical Tomcat 9.0.x.  The
# slightly larger image (+60 MB) is irrelevant for testing; the extra
# `javac` / `jstack` tools actually help when triaging OAuth bean
# wiring failures.
FROM ${BASE_REGISTRY}/library/tomcat:9-jdk11-temurin
COPY --from=build /src/target/oauth.war /usr/local/tomcat/webapps/ROOT.war
COPY jacocoagent.jar /opt/jacoco/jacocoagent.jar
COPY entrypoint.sh /entrypoint.sh
COPY logging.properties /usr/local/tomcat/conf/oauth-logging.properties
RUN chmod +x /entrypoint.sh
EXPOSE 8080 6300
ENTRYPOINT ["/entrypoint.sh"]