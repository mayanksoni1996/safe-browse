#!/bin/bash

# Define the API endpoint
API_URL="https://tranco-list.eu/api/lists/date/latest"

# Fetch the latest Tranco list using curl
echo "Fetching the latest Tranco list..."
response=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$API_URL")

# Extract the HTTP status code
http_status=$(echo "$response" | sed -n 's/.*HTTP_STATUS://p')
response_body=$(echo "$response" | sed -e 's/HTTP_STATUS:.*//g')

# Check if the request was successful
if [ "$http_status" -eq 200 ]; then
    echo "Request successful. Extracting the latest list_id from the response..."
    latest_id=$(echo "$response_body" | jq -r '.list_id')
    echo "Latest list_id: $latest_id"
    echo "Downloading the latest Tranco list..."
    download_url="https://tranco-list.eu/download/$latest_id"
    curl -L -o "${TRANCOFILE_PATH:-tranco_latest.csv}" "$download_url"
    sed -i '' '1s/^/rank,domain\n/' "${TRANCOFILE_PATH:-tranco_latest.csv}"
    export TRANCO_ID="$latest_id"
    echo "Failed to fetch the latest Tranco list. HTTP Status: $http_status"
    echo "Response: $response_body"
    exit 1
fi