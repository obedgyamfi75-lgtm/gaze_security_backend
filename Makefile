# =============================================================================
# GAZE Security Platform - Makefile
# =============================================================================

.PHONY: help build up down logs shell db-init db-migrate admin test lint security-scan

help:
	@echo "GAZE Security Platform - Available Commands"
	@echo "============================================"
	@echo "  make build         - Build Docker images"
	@echo "  make up            - Start all services"
	@echo "  make up-dev        - Start in development mode"
	@echo "  make down          - Stop all services"
	@echo "  make logs          - View logs"
	@echo "  make shell         - Open shell in app container"
	@echo "  make list-routes	- List backend api routes"
	@echo "  make db-init       - Initialize database"
	@echo "  make db-migrate    - Run database migrations"
	@echo "  make admin         - Create admin user"
	@echo "  make test          - Run tests"
	@echo "  make lint          - Run linters"
	@echo "  make security-scan - Run security scans"

# Docker commands
build:
	docker compose build

up:
	docker compose up -d

up-dev:
	docker compose -f docker-compose.dev.yml up -d

down:
	docker compose down

logs:
	docker compose logs -f

list-routes:
	docker compose exec app flask routes

shell:
	docker compose exec app /bin/bash

# Database commands
db-init:
	docker compose exec app flask init-db

db-migrate:
	docker compose exec app flask db migrate

admin:
	docker compose exec app flask create-admin

# Testing
test:
	docker compose exec app pytest tests/ -v --cov=app

# Code quality
lint:
	docker compose exec app black app/ --check
	docker compose exec app isort app/ --check
	docker compose exec app flake8 app/

format:
	docker compose exec app black app/
	docker compose exec app isort app/

# Security scanning
security-scan:
	@echo "Running dependency vulnerability scan..."
	docker compose exec app pip-audit
	@echo ""
	@echo "Running static analysis..."
	docker compose exec app bandit -r app/ -ll
	@echo ""
	@echo "Checking for secrets..."
	docker compose exec app detect-secrets scan app/

# Backup/restore
backup:
	docker compose exec backup /backup.sh

# Clean up
clean:
	docker compose down -v --rmi local
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
