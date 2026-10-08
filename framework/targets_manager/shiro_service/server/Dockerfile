FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests -B

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

COPY --from=builder /build/target/shiro-oauth-server.jar /app/server.jar

# JaCoCo agent for coverage-guided fuzzing
COPY jacoco/ /opt/jacoco/

ENV JAVA_OPTS="-javaagent:/opt/jacoco/jacocoagent.jar=output=tcpserver,address=0.0.0.0,port=6300,includes=com.fuzz.shiro.*"

EXPOSE 8080 6300

HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["sh", "-c", "java $JAVA_OPTS -jar /app/server.jar"]
