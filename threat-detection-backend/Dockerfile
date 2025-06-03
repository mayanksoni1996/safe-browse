FROM gradle:8.13.0-jdk21-ubi-minimal AS builder
WORKDIR /app
COPY . .
RUN gradle build -x test

FROM alpine:latest AS downloader
RUN apk add --no-cache curl jq
ARG API_URL=https://tranco-list.eu/api/lists/date/latest
RUN echo "Fetching the latest Tranco list..." && \
    response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$API_URL") && \
    http_status=$(echo "$response" | sed -n 's/.*HTTP_STATUS://p') && \
    response_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g') && \
    if [ "$http_status" -eq 200 ]; then \
        echo "Request successful. Extracting the latest list_id from the response..."; \
        latest_id=$(echo "$response_body" | jq -r '.list_id'); \
        echo "Latest list_id: $latest_id"; \
        echo "Downloading the latest Tranco list..."; \
        download_url="https://tranco-list.eu/download/$latest_id"; \
        curl -L -o tranco_latest.csv "$download_url"; \
        sed -i '1s/^/rank,domain\n/' tranco_latest.csv; \
        echo "Tranco list downloaded successfully."; \
    else \
        echo "Failed to fetch the latest Tranco list. HTTP Status: $http_status"; \
        echo "Response: $response_body"; \
        exit 1; \
    fi
FROM eclipse-temurin:21.0.6_7-jre-ubi9-minimal
WORKDIR /app
VOLUME /data/trusted
ENV SPRING_PROFILES_ACTIVE=prod
ENV PUBLIC_FQDN=${COOLIFY_FQDN:-localhost}
ENV ARTIFACTORY_PATH=build/libs/*.jar
ENV TRANCOFILE_PATH=/app/tranco_latest.csv
COPY --from=builder /app/build/libs/*.jar /app.jar
COPY --from=downloader tranco_latest.csv /app/tranco_latest.csv
CMD ["java", "-jar", "/app.jar"]
EXPOSE 8080