FROM maven:3.9-eclipse-temurin-17 AS build

WORKDIR /app
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B clean package -DskipTests

FROM eclipse-temurin:17-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-traditional qrencode \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/target/project01-1.0-SNAPSHOT.jar app.jar
COPY templates ./templates

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS:-} -jar app.jar"]
