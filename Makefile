# Makefile for HookProbe v5.0
# Provides convenient commands for common development tasks

.PHONY: help install test lint format clean deploy status

# Default target
.DEFAULT_GOAL := help

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(CYAN)HookProbe Makefile Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ============================================================
# INSTALLATION AND SETUP
# ============================================================

install: ## Install Python dependencies
	@echo "$(CYAN)Installing Python dependencies...$(NC)"
	pip install -r requirements.txt
	@echo "$(GREEN)Dependencies installed$(NC)"

install-dev: ## Install development dependencies
	@echo "$(CYAN)Installing development dependencies...$(NC)"
	pip install pytest pytest-cov flake8 black isort bandit
	@echo "$(GREEN)Development dependencies installed$(NC)"

setup: install install-dev ## Complete development environment setup
	@echo "$(GREEN)Development environment ready!$(NC)"

# ============================================================
# TESTING
# ============================================================

test: ## Run all tests
	@echo "$(CYAN)Running tests...$(NC)"
	pytest tests/

test-verbose: ## Run tests with verbose output
	@echo "$(CYAN)Running tests (verbose)...$(NC)"
	pytest tests/ -vv

test-coverage: ## Run tests with coverage report
	@echo "$(CYAN)Running tests with coverage...$(NC)"
	pytest tests/ --cov=core --cov=shared --cov-report=html --cov-report=term

test-fast: ## Run fast tests only (skip slow tests)
	@echo "$(CYAN)Running fast tests...$(NC)"
	pytest tests/ -m "not slow"

# ============================================================
# CODE QUALITY
# ============================================================

lint: ## Run all linters
	@echo "$(CYAN)Running linters...$(NC)"
	@echo "$(YELLOW)Checking shell scripts...$(NC)"
	-find products/ deploy/ scripts/ -name "*.sh" -type f -exec shellcheck {} \;
	@echo "$(YELLOW)Checking Python code...$(NC)"
	-flake8 core/ shared/ tests/
	@echo "$(GREEN)Linting complete$(NC)"

format: ## Format Python code
	@echo "$(CYAN)Formatting Python code...$(NC)"
	black core/ shared/ tests/
	isort core/ shared/ tests/
	@echo "$(GREEN)Formatting complete$(NC)"

security: ## Run security checks
	@echo "$(CYAN)Running security checks...$(NC)"
	bandit -r core/ shared/ -ll
	@echo "$(GREEN)Security scan complete$(NC)"

check: lint test ## Run linters and tests

# ============================================================
# DEPLOYMENT
# ============================================================

deploy-sentinel: ## Deploy Sentinel tier
	@echo "$(CYAN)Deploying Sentinel...$(NC)"
	sudo ./install.sh --tier sentinel

deploy-guardian: ## Deploy Guardian tier
	@echo "$(CYAN)Deploying Guardian...$(NC)"
	sudo ./install.sh --tier guardian

deploy-fortress: ## Deploy Fortress tier
	@echo "$(CYAN)Deploying Fortress...$(NC)"
	sudo ./install.sh --tier fortress

deploy-nexus: ## Deploy Nexus tier
	@echo "$(CYAN)Deploying Nexus...$(NC)"
	sudo ./install.sh --tier nexus

deploy-mssp: ## Deploy MSSP tier
	@echo "$(CYAN)Deploying MSSP...$(NC)"
	sudo ./install.sh --tier mssp

# ============================================================
# STATUS AND MONITORING
# ============================================================

status: ## Show deployment status
	@echo "$(CYAN)HookProbe Deployment Status$(NC)"
	@echo ""
	@echo "$(YELLOW)Services:$(NC)"
	@systemctl list-units 'hookprobe-*' --no-pager 2>/dev/null || echo "No HookProbe services found"
	@echo ""
	@echo "$(YELLOW)Containers:$(NC)"
	@podman ps -a 2>/dev/null || echo "Podman not available"

logs: ## Show recent logs
	@echo "$(CYAN)Recent HookProbe logs:$(NC)"
	@journalctl -u 'hookprobe-*' --no-pager -n 50 2>/dev/null || echo "No logs found"

health: ## Check service health
	@echo "$(CYAN)Service Health Check$(NC)"
	@echo ""
	@echo "$(YELLOW)Health Endpoint:$(NC)"
	@curl -s http://localhost:9090/health 2>/dev/null || echo "Health endpoint not responding"
	@echo ""

# ============================================================
# CLEANUP
# ============================================================

clean: ## Clean up generated files
	@echo "$(CYAN)Cleaning up...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml 2>/dev/null || true
	@echo "$(GREEN)Cleanup complete$(NC)"

# ============================================================
# VALIDATION
# ============================================================

validate: ## Validate shell scripts
	@echo "$(CYAN)Validating shell scripts...$(NC)"
	@bash -n install.sh && echo "$(GREEN)install.sh is valid$(NC)" || echo "$(RED)install.sh has syntax errors$(NC)"
	@find products/ -name "setup.sh" -exec bash -n {} \; -exec echo "$(GREEN){} is valid$(NC)" \;
	@find products/ -name "uninstall.sh" -exec bash -n {} \; -exec echo "$(GREEN){} is valid$(NC)" \;

validate-repo: ## Run repository cleanup validator
	@echo "$(CYAN)Running repository cleanup validator...$(NC)"
	./scripts/repo-cleanup-validator.sh

# ============================================================
# VERSION INFO
# ============================================================

version: ## Show version information
	@echo "$(CYAN)HookProbe Version Information$(NC)"
	@echo "Version: 5.0.0"
	@echo "License: MIT"
	@echo "Python: $$(python3 --version 2>/dev/null || echo 'Not installed')"
	@echo "Podman: $$(podman --version 2>/dev/null || echo 'Not installed')"
