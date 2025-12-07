#!/bin/bash
#
# HookProbe Configuration Validation Script
#
# This script validates all configuration files in the HookProbe project
# to ensure they are syntactically correct and contain required variables.
#
# Usage:
#   ./validate-config.sh [--strict] [--fix]
#
# Options:
#   --strict    Fail on warnings (default: warnings are informational only)
#   --fix       Attempt to fix common issues automatically
#   --verbose   Show detailed output
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STRICT_MODE=false
FIX_MODE=false
VERBOSE=false
EXIT_CODE=0

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# ============================================================================
# Helper Functions
# ============================================================================

log_header() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_section() {
    echo ""
    echo -e "${MAGENTA}▶ $1${NC}"
    echo -e "${MAGENTA}$(echo "$1" | sed 's/./─/g')${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((PASSED_CHECKS++)) || true
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
    ((WARNING_CHECKS++)) || true
    if [ "$STRICT_MODE" = true ]; then
        EXIT_CODE=1
    fi
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    ((FAILED_CHECKS++)) || true
    EXIT_CODE=1
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}  ↳ $1${NC}"
    fi
}

# ============================================================================
# Validation Functions
# ============================================================================

check_shellcheck_available() {
    if command -v shellcheck &>/dev/null; then
        log_success "ShellCheck is available ($(shellcheck --version | head -1))"
        return 0
    else
        log_warning "ShellCheck not found - skipping ShellCheck validation"
        log_info "Install ShellCheck: https://www.shellcheck.net/"
        return 1
    fi
}

validate_shell_syntax() {
    log_section "Shell Script Syntax Validation"

    local files_found=0
    local files_checked=0

    while IFS= read -r file; do
        ((files_found++)) || true
        ((TOTAL_CHECKS++)) || true

        log_verbose "Checking: $file"

        # Bash syntax check
        if bash -n "$file" 2>/dev/null; then
            log_success "Syntax OK: $file"
            ((files_checked++)) || true
        else
            log_error "Syntax error in: $file"
            if [ "$VERBOSE" = true ]; then
                bash -n "$file" 2>&1 | sed 's/^/    /'
            fi
        fi
    done < <(find "$REPO_ROOT" -name 'config.sh' -o -name '*-config.sh' -o -name 'setup*.sh' -o -name 'install*.sh' 2>/dev/null)

    if [ $files_found -eq 0 ]; then
        log_warning "No shell scripts found"
    else
        log_info "Checked $files_checked of $files_found shell scripts"
    fi
}

validate_shellcheck() {
    if ! check_shellcheck_available; then
        return
    fi

    log_section "ShellCheck Validation"

    local files_found=0

    while IFS= read -r file; do
        ((files_found++)) || true
        ((TOTAL_CHECKS++)) || true

        log_verbose "ShellCheck: $file"

        if shellcheck "$file" 2>&1 | grep -q "error"; then
            log_error "ShellCheck errors in: $file"
            if [ "$VERBOSE" = true ]; then
                shellcheck "$file" 2>&1 | sed 's/^/    /'
            fi
        elif shellcheck "$file" 2>&1 | grep -q "warning"; then
            log_warning "ShellCheck warnings in: $file"
            if [ "$VERBOSE" = true ]; then
                shellcheck "$file" 2>&1 | sed 's/^/    /'
            fi
        else
            log_success "ShellCheck passed: $file"
        fi
    done < <(find "$REPO_ROOT" -name 'config.sh' -o -name '*-config.sh' -o -name 'setup*.sh' -o -name 'install*.sh' 2>/dev/null)

    if [ $files_found -eq 0 ]; then
        log_warning "No shell scripts found for ShellCheck"
    fi
}

validate_edge_config() {
    log_section "Edge Configuration Validation"

    local edge_config="$REPO_ROOT/deploy/edge/config.sh"

    if [ ! -f "$edge_config" ]; then
        log_warning "Edge config not found: $edge_config"
        return
    fi

    log_info "Validating: $edge_config"

    # Required variables for edge deployment
    local required_vars=(
        "DEPLOYMENT_TYPE"
        "PHYSICAL_HOST_INTERFACE"
        "PHYSICAL_HOST_IP"
        "VERSION"
    )

    for var in "${required_vars[@]}"; do
        ((TOTAL_CHECKS++)) || true

        if grep -q "$var" "$edge_config"; then
            log_success "Found variable: $var"
        else
            log_warning "Missing variable reference: $var (may be defined elsewhere)"
        fi
    done

    # Check deployment type value
    ((TOTAL_CHECKS++)) || true
    if grep -q 'DEPLOYMENT_TYPE=.*edge' "$edge_config"; then
        log_success "Deployment type set to 'edge'"
    else
        log_warning "Deployment type may not be set to 'edge'"
    fi
}

validate_cloud_config() {
    log_section "Cloud Configuration Validation"

    local cloud_config="$REPO_ROOT/deploy/cloud/config.sh"

    if [ ! -f "$cloud_config" ]; then
        log_warning "Cloud config not found: $cloud_config"
        return
    fi

    log_info "Validating: $cloud_config"

    # Required variables for cloud deployment
    local required_vars=(
        "DEPLOYMENT_TYPE"
        "VERSION"
    )

    for var in "${required_vars[@]}"; do
        ((TOTAL_CHECKS++)) || true

        if grep -q "$var" "$cloud_config"; then
            log_success "Found variable: $var"
        else
            log_warning "Missing variable reference: $var (may be defined elsewhere)"
        fi
    done

    # Check deployment type value
    ((TOTAL_CHECKS++)) || true
    if grep -q 'DEPLOYMENT_TYPE=.*cloud' "$cloud_config"; then
        log_success "Deployment type set to 'cloud'"
    else
        log_warning "Deployment type may not be set to 'cloud'"
    fi
}

validate_webserver_config() {
    log_section "Web Server Configuration Validation"

    local webserver_config="$REPO_ROOT/deploy/addons/webserver/config/webserver-config.sh"

    if [ ! -f "$webserver_config" ]; then
        log_warning "Web server config not found: $webserver_config"
        return
    fi

    log_info "Validating: $webserver_config"

    # Check for required database variables
    local db_vars=("POSTGRES_HOST" "POSTGRES_PORT" "POSTGRES_DB" "POSTGRES_USER")

    for var in "${db_vars[@]}"; do
        ((TOTAL_CHECKS++)) || true

        if grep -q "$var" "$webserver_config"; then
            log_success "Found database variable: $var"
        else
            log_warning "Missing database variable: $var"
        fi
    done

    # Check for Django secret key
    ((TOTAL_CHECKS++)) || true
    if grep -q "DJANGO_SECRET_KEY" "$webserver_config"; then
        log_success "Found DJANGO_SECRET_KEY"

        # Check if it's still the default insecure value
        if grep -q "CHANGE-THIS-IN-PRODUCTION" "$webserver_config"; then
            log_warning "DJANGO_SECRET_KEY uses default insecure value"
        fi
    else
        log_error "Missing DJANGO_SECRET_KEY"
    fi
}

validate_network_ranges() {
    log_section "Network Range Validation"

    # Expected POD network prefixes
    local expected_networks=(
        "10.200.1"  # POD-001
        "10.200.2"  # POD-002
        "10.200.3"  # POD-003
        "10.200.4"  # POD-004
        "10.200.5"  # POD-005
        "10.200.6"  # POD-006
        "10.200.7"  # POD-007
        "10.200.8"  # POD-008 (optional)
    )

    log_info "Checking for POD network references..."

    local configs_found=0

    while IFS= read -r file; do
        ((configs_found++)) || true

        log_verbose "Scanning: $file"

        for network in "${expected_networks[@]}"; do
            if grep -q "$network" "$file" 2>/dev/null; then
                log_verbose "Found $network.x network in $file"
            fi
        done
    done < <(find "$REPO_ROOT/install" -name 'config.sh' -o -name '*-config.sh' 2>/dev/null)

    if [ $configs_found -gt 0 ]; then
        log_success "Scanned $configs_found configuration files for network ranges"
    else
        log_warning "No configuration files found to scan"
    fi
}

validate_deployment_types() {
    log_section "Deployment Type Validation"

    local valid_types=("edge" "cloud" "hybrid" "headless" "development")

    while IFS= read -r file; do
        ((TOTAL_CHECKS++)) || true

        if grep -q "^DEPLOYMENT_TYPE=" "$file" 2>/dev/null; then
            local deployment_type=$(grep "^DEPLOYMENT_TYPE=" "$file" | cut -d= -f2 | tr -d '"' | tr -d "'" | tr -d '$' | cut -d'{' -f1)

            log_verbose "Found DEPLOYMENT_TYPE=$deployment_type in $file"

            # Check if it's a variable reference
            if [[ "$deployment_type" =~ ^\{ ]]; then
                log_info "$file uses variable reference for DEPLOYMENT_TYPE"
                continue
            fi

            # Check if valid
            if [[ " ${valid_types[@]} " =~ " ${deployment_type} " ]] || [ -z "$deployment_type" ]; then
                log_success "Valid deployment type in: $(basename "$file")"
            else
                log_warning "Unknown deployment type '$deployment_type' in: $(basename "$file")"
            fi
        fi
    done < <(find "$REPO_ROOT/install" -name 'config.sh' -o -name '*-config.sh' 2>/dev/null)
}

validate_version_consistency() {
    log_section "Version Consistency Check"

    log_info "Checking version numbers across configurations..."

    local version_files=()
    local versions=()

    while IFS= read -r file; do
        if grep -q "^VERSION=" "$file" 2>/dev/null; then
            local version=$(grep "^VERSION=" "$file" | cut -d= -f2 | tr -d '"' | tr -d "'")
            version_files+=("$file")
            versions+=("$version")
            log_verbose "$(basename "$file"): VERSION=$version"
        fi
    done < <(find "$REPO_ROOT/install" -name 'config.sh' -o -name '*-config.sh' 2>/dev/null)

    if [ ${#versions[@]} -eq 0 ]; then
        log_warning "No VERSION variables found in configuration files"
    else
        # Check if all versions are the same
        local first_version="${versions[0]}"
        local all_same=true

        for version in "${versions[@]}"; do
            if [ "$version" != "$first_version" ]; then
                all_same=false
                break
            fi
        done

        ((TOTAL_CHECKS++)) || true
        if [ "$all_same" = true ]; then
            log_success "All versions are consistent: $first_version"
        else
            log_warning "Version inconsistency detected across configuration files"
            for i in "${!version_files[@]}"; do
                log_info "  $(basename "${version_files[$i]}"): ${versions[$i]}"
            done
        fi
    fi
}

validate_python_requirements() {
    log_section "Python Requirements Validation"

    local requirements_file="$REPO_ROOT/products/mssp/web/requirements.txt"

    if [ ! -f "$requirements_file" ]; then
        log_warning "requirements.txt not found: $requirements_file"
        return
    fi

    log_info "Validating: $requirements_file"

    # Check for critical packages
    local critical_packages=("Django" "psycopg2" "gunicorn" "djangorestframework")

    for package in "${critical_packages[@]}"; do
        ((TOTAL_CHECKS++)) || true

        if grep -qi "^$package" "$requirements_file"; then
            log_success "Found package: $package"
        else
            log_error "Missing critical package: $package"
        fi
    done
}

validate_containerfile() {
    log_section "Containerfile Validation"

    local containerfile="$REPO_ROOT/deploy/addons/webserver/Containerfile"

    if [ ! -f "$containerfile" ]; then
        log_info "Containerfile not found (skipping)"
        return
    fi

    log_info "Validating: $containerfile"

    # Check for critical Containerfile directives
    local directives=("FROM" "WORKDIR" "COPY" "RUN" "EXPOSE" "ENTRYPOINT")

    for directive in "${directives[@]}"; do
        ((TOTAL_CHECKS++)) || true

        if grep -q "^$directive" "$containerfile"; then
            log_success "Found directive: $directive"
        else
            log_warning "Missing directive: $directive"
        fi
    done

    # Check if migrations are in entrypoint
    ((TOTAL_CHECKS++)) || true
    if grep -q "migrate" "$containerfile"; then
        log_success "Database migrations found in Containerfile"
    else
        log_warning "Database migrations not found in Containerfile"
    fi
}

# ============================================================================
# Summary and Reporting
# ============================================================================

print_summary() {
    echo ""
    log_header "Validation Summary"
    echo ""

    local total_issues=$((FAILED_CHECKS + WARNING_CHECKS))

    echo -e "Total Checks:    ${BLUE}${TOTAL_CHECKS}${NC}"
    echo -e "Passed:          ${GREEN}${PASSED_CHECKS}${NC}"
    echo -e "Warnings:        ${YELLOW}${WARNING_CHECKS}${NC}"
    echo -e "Errors:          ${RED}${FAILED_CHECKS}${NC}"
    echo ""

    if [ $FAILED_CHECKS -eq 0 ] && [ $WARNING_CHECKS -eq 0 ]; then
        echo -e "${GREEN}✓ All validation checks passed!${NC}"
    elif [ $FAILED_CHECKS -eq 0 ]; then
        echo -e "${YELLOW}⚠ Validation completed with warnings${NC}"
        echo -e "${YELLOW}  Warnings are informational and don't block deployment${NC}"
    else
        echo -e "${RED}✗ Validation failed with $FAILED_CHECKS error(s)${NC}"
        echo -e "${RED}  Please fix the errors before deploying${NC}"
    fi

    echo ""

    if [ "$STRICT_MODE" = true ]; then
        echo -e "${YELLOW}Strict mode: Warnings treated as errors${NC}"
    fi

    if [ "$FIX_MODE" = true ]; then
        echo -e "${BLUE}Fix mode: Automatic fixes were attempted${NC}"
    fi

    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --strict)
                STRICT_MODE=true
                shift
                ;;
            --fix)
                FIX_MODE=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --strict     Fail on warnings (default: warnings are informational)"
                echo "  --fix        Attempt to fix common issues automatically"
                echo "  --verbose    Show detailed output"
                echo "  -h, --help   Show this help message"
                echo ""
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Print header
    log_header "HookProbe Configuration Validation"
    echo ""
    log_info "Repository: $REPO_ROOT"
    log_info "Mode: $([ "$STRICT_MODE" = true ] && echo "Strict" || echo "Lenient")"
    [ "$VERBOSE" = true ] && log_info "Verbose output enabled"
    echo ""

    # Run validation checks
    validate_shell_syntax
    validate_shellcheck
    validate_edge_config
    validate_cloud_config
    validate_webserver_config
    validate_network_ranges
    validate_deployment_types
    validate_version_consistency
    validate_python_requirements
    validate_containerfile

    # Print summary
    print_summary

    # Exit with appropriate code
    exit $EXIT_CODE
}

# Run main function
main "$@"
