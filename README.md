# Phishing Detection System

This repository contains a **reactive phishing detection system** built with **Spring Boot** and **MongoDB**. The system identifies potential phishing attempts by comparing requested domains against a curated list of trusted domains using **edit distance** calculations.

---

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [How It Works](#how-it-works)
- [Setup and Deployment](#setup-and-deployment)

---

## Introduction

In an increasingly interconnected digital landscape, phishing attacks remain a significant threat. This system aims to provide a robust, reactive solution for identifying potentially malicious domains by leveraging a database of trusted domains and calculating edit distances. It is designed to be lightweight and easily deployable via Docker.

---

## Features

- **Reactive Architecture**: Built with Spring WebFlux for high throughput and non-blocking operations.
- **Trusted Domain Management**: Automatically downloads and maintains a list of trusted domains from [Tranco](https://tranco-list.eu/).
- **Edit Distance Analysis**: Utilizes Levenshtein distance to compare requested domains against trusted ones.
- **Phishing Classification**: Classifies domains as `NOT_PHISHING`, `POSSIBLE_PHISHING`, or `PHISHING` based on configurable edit distance thresholds.
- **Dockerized Deployment**: Bundled into a minimal Docker container using multi-stage builds.
- **Domain Whitelisting**: Supports a configurable whitelist to bypass detection for known safe domains.

---

## Technologies Used

### Backend
- Spring Boot
- Spring WebFlux
- Spring Data MongoDB Reactive

### Database
- MongoDB

### Containerization
- Docker

### Utilities
- `curl` – for downloading Tranco lists
- `jq` – for parsing JSON from Tranco lists

---

## How It Works

### 1. Trusted Domain Ingestion

- At startup or via a scheduled job:
    - A script fetches the latest Tranco list index using `curl`.
    - `jq` is used to parse the JSON response to extract the latest list URL.
    - The domain list is then downloaded and inserted into MongoDB.

### 2. Domain Request Processing

- When a domain request is received:
    - **TLD Extraction**: Extracts the TLD (e.g., `.com`) from the requested domain to query only relevant trusted domains.
    - **Edit Distance Calculation**: Compares the domain against the relevant trusted domains using Levenshtein distance.
    - **Phishing Classification**:
        - Distance = 0 → `NOT_PHISHING`
        - Distance ≤ 2 → `POSSIBLE_PHISHING` (configurable threshold)
        - Distance > 2 → `NOT_PHISHING`

### 3. State Management & Redirection

- The requested domain is temporarily cached for context.
- If classified as `POSSIBLE_PHISHING`, the user may be redirected to a confirmation page (e.g., Google Safe Browsing).

---

## Setup and Deployment

### Prerequisites

- Docker
- Docker Compose (recommended for local development)
- MongoDB instance (local or remote)

### Configuration

- MongoDB connection details via `MONGO_URI` environment variable
- Tranco list URL and refresh interval can be configured in the application properties

### Build Docker Image

```bash
docker build -t phishing-detector .
