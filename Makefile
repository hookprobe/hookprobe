# Makefile for HookProbe
# Provides convenient commands for common development tasks

.PHONY: help install test lint format clean deploy undeploy status

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
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev: ## Install development dependencies
	@echo "$(CYAN)Installing development dependencies...$(NC)"
	pip install -r requirements-dev.txt
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

install-hooks: ## Install pre-commit hooks
	@echo "$(CYAN)Installing pre-commit hooks...$(NC)"
	pre-commit install
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"

setup: install install-dev install-hooks ## Complete development environment setup
	@echo "$(GREEN)✓ Development environment ready!$(NC)"

# ============================================================
# TESTING
# ============================================================

test: ## Run all tests
	@echo "$(CYAN)Running tests...$(NC)"
	pytest

test-verbose: ## Run tests with verbose output
	@echo "$(CYAN)Running tests (verbose)...$(NC)"
	pytest -vv

test-coverage: ## Run tests with coverage report
	@echo "$(CYAN)Running tests with coverage...$(NC)"
	pytest --cov=Scripts/autonomous --cov-report=html --cov-report=term

test-fast: ## Run fast tests only (skip slow tests)
	@echo "$(CYAN)Running fast tests...$(NC)"
	pytest -m "not slow"

# ============================================================
# CODE QUALITY
# ============================================================

lint: ## Run all linters
	@echo "$(CYAN)Running linters...$(NC)"
	@echo "$(YELLOW)Checking shell scripts...$(NC)"
	-find Scripts -name "*.sh" -type f -exec shellcheck {} \;
	@echo "$(YELLOW)Checking Python code...$(NC)"
	-flake8 Scripts/autonomous/qsecbit.py
	-pylint Scripts/autonomous/qsecbit.py
	@echo "$(GREEN)✓ Linting complete$(NC)"

lint-fix: ## Run linters with auto-fix
	@echo "$(CYAN)Running linters with auto-fix...$(NC)"
	black Scripts/autonomous/qsecbit.py
	isort Scripts/autonomous/qsecbit.py
	@echo "$(GREEN)✓ Auto-fixes applied$(NC)"

format: lint-fix ## Format code (alias for lint-fix)

security: ## Run security checks
	@echo "$(CYAN)Running security checks...$(NC)"
	bandit -r Scripts/ -ll
	@echo "$(GREEN)✓ Security scan complete$(NC)"

check: lint test ## Run linters and tests

# ============================================================
# DEPLOYMENT
# ============================================================

deploy: ## Deploy HookProbe (requires root)
	@echo "$(CYAN)Deploying HookProbe...$(NC)"
	@echo "$(YELLOW)This requires root privileges$(NC)"
	cd Scripts/autonomous/install && sudo ./setup.sh

deploy-n8n: ## Deploy n8n automation (POD 008)
	@echo "$(CYAN)Deploying n8n...$(NC)"
	@echo "$(YELLOW)This requires root privileges$(NC)"
	cd Scripts/autonomous/install && sudo ./n8n_setup.sh

undeploy: ## Remove HookProbe deployment
	@echo "$(CYAN)Removing HookProbe deployment...$(NC)"
	@echo "$(RED)This will remove all PODs and containers$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		cd Scripts/autonomous/install && sudo ./uninstall.sh; \
	fi

undeploy-n8n: ## Remove n8n deployment (POD 008)
	@echo "$(CYAN)Removing n8n deployment...$(NC)"
	cd Scripts/autonomous/install && sudo ./n8n_uninstall.sh

# ============================================================
# STATUS AND MONITORING
# ============================================================

status: ## Show deployment status
	@echo "$(CYAN)HookProbe Deployment Status$(NC)"
	@echo ""
	@echo "$(YELLOW)PODs:$(NC)"
	@podman pod ps || echo "$(RED)Podman not available or no PODs running$(NC)"
	@echo ""
	@echo "$(YELLOW)Containers:$(NC)"
	@podman ps -a || echo "$(RED)No containers$(NC)"
	@echo ""
	@echo "$(YELLOW)OVS Bridge:$(NC)"
	@ovs-vsctl show || echo "$(RED)OVS not available$(NC)"

logs: ## Show recent logs from all containers
	@echo "$(CYAN)Recent container logs:$(NC)"
	@for pod in $$(podman pod ps --format "{{.Name}}" 2>/dev/null); do \
		echo "$(YELLOW)$$pod:$(NC)"; \
		podman pod logs --tail 10 $$pod 2>/dev/null || echo "$(RED)No logs$(NC)"; \
		echo ""; \
	done

health: ## Check service health
	@echo "$(CYAN)Service Health Check$(NC)"
	@echo ""
	@echo "$(YELLOW)Django:$(NC)"
	@curl -s -o /dev/null -w "%{http_code}" http://localhost/ || echo "Not responding"
	@echo ""
	@echo "$(YELLOW)Grafana:$(NC)"
	@curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ || echo "Not responding"
	@echo ""
	@echo "$(YELLOW)Qsecbit:$(NC)"
	@curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/health || echo "Not responding"
	@echo ""

# ============================================================
# CLEANUP
# ============================================================

clean: ## Clean up generated files
	@echo "$(CYAN)Cleaning up...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

clean-all: clean ## Deep clean including deployment artifacts
	@echo "$(CYAN)Deep cleaning...$(NC)"
	@echo "$(RED)This will remove test artifacts and build files$(NC)"
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true
	rm -rf .mypy_cache/ .tox/ .nox/ 2>/dev/null || true
	@echo "$(GREEN)✓ Deep clean complete$(NC)"

# ============================================================
# DOCUMENTATION
# ============================================================

docs: ## Generate documentation
	@echo "$(CYAN)Generating documentation...$(NC)"
	@echo "$(YELLOW)Documentation generation not yet implemented$(NC)"
	@echo "$(YELLOW)See README.md and CLAUDE.md for now$(NC)"

# ============================================================
# DEVELOPMENT
# ============================================================

dev-shell: ## Start development shell with venv activated
	@echo "$(CYAN)Starting development shell...$(NC)"
	@echo "$(YELLOW)Run 'deactivate' to exit$(NC)"
	@if [ -d "venv" ]; then \
		. venv/bin/activate && exec $$SHELL; \
	else \
		echo "$(RED)No venv found. Run 'make venv' first$(NC)"; \
	fi

venv: ## Create Python virtual environment
	@echo "$(CYAN)Creating virtual environment...$(NC)"
	python3 -m venv venv
	@echo "$(GREEN)✓ Virtual environment created$(NC)"
	@echo "$(YELLOW)Activate with: source venv/bin/activate$(NC)"

# ============================================================
# VALIDATION
# ============================================================

validate: ## Validate configuration files
	@echo "$(CYAN)Validating configuration files...$(NC)"
	@bash -n Scripts/autonomous/install/network-config.sh && echo "$(GREEN)✓ network-config.sh is valid$(NC)" || echo "$(RED)✗ network-config.sh has syntax errors$(NC)"
	@bash -n Scripts/autonomous/install/setup.sh && echo "$(GREEN)✓ setup.sh is valid$(NC)" || echo "$(RED)✗ setup.sh has syntax errors$(NC)"
	@bash -n Scripts/autonomous/install/uninstall.sh && echo "$(GREEN)✓ uninstall.sh is valid$(NC)" || echo "$(RED)✗ uninstall.sh has syntax errors$(NC)"

# ============================================================
# RELEASE
# ============================================================

version: ## Show version information
	@echo "$(CYAN)HookProbe Version Information$(NC)"
	@echo "Version: 5.0.0"
	@echo "License: MIT"
	@echo "Python: $$(python3 --version)"
	@echo "Podman: $$(podman --version 2>/dev/null || echo 'Not installed')"
	@echo "OVS: $$(ovs-vsctl --version 2>/dev/null | head -1 || echo 'Not installed')"
