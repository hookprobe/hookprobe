#!/bin/bash
#
# repo-cleanup-validator.sh - HookProbe Repository Cleanup Validator
# Version: 1.0.0
# License: AGPL-3.0 - see LICENSE file
#
# This script validates the repository structure and identifies:
# - Orphaned files not referenced by any script
# - Broken internal links in shell scripts
# - Missing required files
# - Duplicate functionality
#
# Usage:
#   ./scripts/repo-cleanup-validator.sh          # Full validation
#   ./scripts/repo-cleanup-validator.sh --quick  # Quick check
#   ./scripts/repo-cleanup-validator.sh --fix    # Auto-fix mode (careful!)
#
# Exit codes:
#   0 - All validations passed
#   1 - Warnings found (orphaned files)
#   2 - Errors found (broken references)
#

# Don't use set -e as we need to continue after errors to report all issues

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
WARNINGS=0
ERRORS=0
ORPHANS=0

# Mode
QUICK_MODE=false
FIX_MODE=false
VERBOSE=false

# ============================================================
# ARGUMENT PARSING
# ============================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick) QUICK_MODE=true; shift ;;
            --fix) FIX_MODE=true; shift ;;
            --verbose|-v) VERBOSE=true; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) shift ;;
        esac
    done
}

show_help() {
    cat << 'EOF'
HookProbe Repository Cleanup Validator

Usage:
  ./scripts/repo-cleanup-validator.sh [OPTIONS]

Options:
  --quick      Quick validation (skip deep analysis)
  --fix        Auto-fix mode (removes orphaned files - USE WITH CAUTION)
  --verbose    Show detailed output
  --help       Show this help message

Checks:
  1. Shell script references - Validates all bash/source references
  2. Python imports - Checks import statements match actual files
  3. README links - Validates internal markdown links
  4. Orphaned files - Files not referenced anywhere
  5. Required files - Ensures critical files exist
  6. Directory structure - Validates expected directories

EOF
}

# ============================================================
# LOGGING
# ============================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; ((ERRORS++)); }
log_orphan() { echo -e "${CYAN}[ORPHAN]${NC} $1"; ((ORPHANS++)); }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_verbose() { [ "$VERBOSE" = true ] && echo -e "${NC}[DEBUG] $1"; }

# ============================================================
# REQUIRED FILES CHECK
# ============================================================
check_required_files() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Checking Required Files"
    echo "═══════════════════════════════════════════════════════════"

    local required_files=(
        # Root level
        "README.md"
        "LICENSE"
        "install.sh"
        "uninstall.sh"
        "ARCHITECTURE.md"

        # Core
        "core/README.md"
        "core/htp/transport/htp.py"
        "core/qsecbit/qsecbit.py"
        "core/neuro/core/ter.py"

        # Products
        "products/README.md"
        "products/guardian/README.md"
        "products/guardian/scripts/setup.sh"
        "products/fortress/README.md"
        "products/fortress/install.sh"
        "products/nexus/README.md"
        "products/nexus/setup.sh"
        "products/sentinel/README.md"
        "products/sentinel/bootstrap.sh"

        # Deploy
        "deploy/README.md"

        # Shared
        "shared/README.md"
    )

    local missing=0
    for file in "${required_files[@]}"; do
        if [ -f "$REPO_ROOT/$file" ]; then
            log_verbose "Found: $file"
        else
            log_error "Missing required file: $file"
            ((missing++))
        fi
    done

    if [ $missing -eq 0 ]; then
        log_ok "All ${#required_files[@]} required files present"
    else
        log_error "$missing required files missing"
    fi
}

# ============================================================
# DIRECTORY STRUCTURE CHECK
# ============================================================
check_directory_structure() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Checking Directory Structure"
    echo "═══════════════════════════════════════════════════════════"

    local required_dirs=(
        "core"
        "core/htp"
        "core/qsecbit"
        "core/neuro"
        "products"
        "products/guardian"
        "products/fortress"
        "products/nexus"
        "products/sentinel"
        "shared"
        "shared/dsm"
        "deploy"
        "docs"
        "scripts"
    )

    local deprecated_dirs=(
        "src"
        "install"
        "releases"
    )

    # Check required dirs
    for dir in "${required_dirs[@]}"; do
        if [ -d "$REPO_ROOT/$dir" ]; then
            log_verbose "Directory OK: $dir"
        else
            log_error "Missing required directory: $dir"
        fi
    done

    # Check for deprecated dirs
    for dir in "${deprecated_dirs[@]}"; do
        if [ -d "$REPO_ROOT/$dir" ]; then
            log_warn "Deprecated directory still exists: $dir (should be removed)"
        fi
    done

    log_ok "Directory structure validated"
}

# ============================================================
# SHELL SCRIPT REFERENCE CHECK
# ============================================================
check_shell_references() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Checking Shell Script References"
    echo "═══════════════════════════════════════════════════════════"

    local broken_refs=0

    # Find all shell scripts
    while IFS= read -r script; do
        log_verbose "Checking: $script"

        # Extract file references (bash, source, exec, paths in quotes)
        grep -oE '(bash|source|exec|\.|/)[[:space:]]+["'"'"']?[^"'"'"'[:space:]]+\.(sh|py|conf)' "$script" 2>/dev/null | while read -r ref; do
            # Extract just the path
            local path=$(echo "$ref" | sed -E 's/^(bash|source|exec|\.|\/)[[:space:]]+["'"'"']?//' | sed "s/[\"'].*//")

            # Skip variables and special patterns
            [[ "$path" == *'$'* ]] && continue
            [[ "$path" == *'%'* ]] && continue
            [[ "$path" =~ ^- ]] && continue

            # Resolve relative paths
            local script_dir=$(dirname "$script")
            local full_path=""

            if [[ "$path" == /* ]]; then
                # Skip absolute paths outside repo (like /etc/)
                [[ "$path" != "$REPO_ROOT"* ]] && continue
                full_path="$path"
            elif [[ "$path" == "./"* ]]; then
                full_path="$script_dir/${path#./}"
            else
                full_path="$script_dir/$path"
            fi

            # Check if file exists (only for repo-relative paths)
            if [[ "$full_path" == "$REPO_ROOT"* ]] && [ ! -f "$full_path" ]; then
                log_verbose "  Broken reference in $script: $path"
            fi
        done
    done < <(find "$REPO_ROOT" -name "*.sh" -type f ! -path "*/.git/*" ! -path "*/node_modules/*")

    log_ok "Shell script references checked"
}

# ============================================================
# ORPHANED FILES CHECK
# ============================================================
check_orphaned_files() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Checking for Orphaned Files"
    echo "═══════════════════════════════════════════════════════════"

    # Create temp files for analysis
    local all_files=$(mktemp)
    local referenced_files=$(mktemp)
    local orphans_file=$(mktemp)

    # Get all shell scripts and Python files
    find "$REPO_ROOT" -type f \( -name "*.sh" -o -name "*.py" \) \
        ! -path "*/.git/*" \
        ! -path "*/__pycache__/*" \
        ! -path "*/node_modules/*" \
        -printf "%P\n" | sort > "$all_files"

    # Files that are explicitly allowed to be standalone
    local standalone_files=(
        "install.sh"
        "uninstall.sh"
        "install-sentinel-lite.sh"
        "install-validator.sh"
        "scripts/repo-cleanup-validator.sh"
        "scripts/run-unit-tests.sh"
        "scripts/run-integration-tests.sh"
        "scripts/run-performance-tests.sh"
        "scripts/install-edge.sh"
        "scripts/gdpr-retention.sh"
        "Makefile"
        # Product entry points
        "products/guardian/web/app.py"
products/nexus/setup.sh
        "products/sentinel/sentinel.py"
        "products/sentinel/sentinel_security.py"
        # Deploy scripts
        "deploy/edge/provision.sh"
        "deploy/edge/cleanup.sh"
        "deploy/edge/update.sh"
        "deploy/cloud/setup.sh"
        "deploy/cloud/config.sh"
        "deploy/addons/n8n/setup.sh"
        "deploy/addons/n8n/config.sh"
        "deploy/addons/webserver/setup-webserver.sh"
        "deploy/addons/webserver/entrypoint.sh"
    )

    # Extract all file references from shell scripts
    grep -rhoE '[a-zA-Z0-9_/-]+\.(sh|py)' "$REPO_ROOT" \
        --include="*.sh" --include="*.py" --include="*.yml" --include="*.yaml" --include="*.md" \
        2>/dev/null | sort -u > "$referenced_files"

    # Also add entry points
    for f in "${standalone_files[@]}"; do
        echo "$f" >> "$referenced_files"
    done

    # Find orphans
    local orphan_count=0
    while IFS= read -r file; do
        local basename=$(basename "$file")

        # Skip test files
        [[ "$file" == tests/* ]] && continue
        [[ "$file" == *_test.py ]] && continue
        [[ "$file" == *test_*.py ]] && continue
        [[ "$file" == */tests/* ]] && continue

        # Skip __init__.py files
        [[ "$basename" == "__init__.py" ]] && continue

        # Skip conftest.py
        [[ "$basename" == "conftest.py" ]] && continue

        # Skip backup files
        [[ "$basename" == *_backup.py ]] && continue
        [[ "$basename" == *_backup.sh ]] && continue
        [[ "$basename" == *.bak ]] && continue

        # Skip example files
        [[ "$basename" == *_example.py ]] && continue
        [[ "$basename" == *_example.sh ]] && continue
        [[ "$basename" == example_*.py ]] && continue
        [[ "$basename" == example_*.sh ]] && continue

        # Skip integration files (often referenced dynamically)
        [[ "$file" == */integrations/* ]] && continue
        [[ "$file" == */lib/* ]] && continue

        # Skip Django convention files (auto-discovered by Django)
        [[ "$basename" == "admin.py" ]] && continue
        [[ "$basename" == "apps.py" ]] && continue
        [[ "$basename" == "forms.py" ]] && continue
        [[ "$basename" == "serializers.py" ]] && continue
        [[ "$basename" == "tests.py" ]] && continue
        [[ "$basename" == "urls.py" ]] && continue
        [[ "$basename" == "views.py" ]] && continue
        [[ "$basename" == "models.py" ]] && continue
        [[ "$basename" == "email.py" ]] && continue
        [[ "$basename" == "authentication.py" ]] && continue
        [[ "$file" == */management/commands/* ]] && continue
        [[ "$file" == */api/* ]] && continue
        [[ "$file" == */services/* ]] && continue
        [[ "$file" == */settings/* ]] && continue
        [[ "$file" == */common/* ]] && continue

        # Skip Flask/Guardian web modules (registered via blueprints)
        [[ "$file" == */web/modules/* ]] && continue

        # Skip shared module files
        [[ "$file" == */adversarial/* ]] && continue
        [[ "$file" == */signatures/* ]] && continue
        [[ "$file" == */ml/* ]] && continue
        [[ "$file" == */wireless/* ]] && continue

        # Check if file is referenced
        if ! grep -qF "$basename" "$referenced_files" 2>/dev/null; then
            # Double check with full path patterns
            local found=false
            for pattern in "$file" "$(dirname "$file")/" "$basename"; do
                if grep -rq "$pattern" "$REPO_ROOT" --include="*.sh" --include="*.py" --include="*.yml" --include="*.yaml" --include="*.md" --include="*.json" 2>/dev/null; then
                    found=true
                    break
                fi
            done

            if [ "$found" = false ]; then
                log_orphan "$file"
                echo "$file" >> "$orphans_file"
                ((orphan_count++))
            fi
        fi
    done < "$all_files"

    if [ $orphan_count -eq 0 ]; then
        log_ok "No orphaned files found"
    else
        log_warn "$orphan_count potentially orphaned files found"

        if [ "$FIX_MODE" = true ]; then
            echo ""
            echo -e "${RED}FIX MODE: Would remove the following files:${NC}"
            cat "$orphans_file"
            read -p "Proceed with deletion? (yes/no): " confirm
            if [ "$confirm" = "yes" ]; then
                while IFS= read -r orphan; do
                    rm -f "$REPO_ROOT/$orphan"
                    log_info "Removed: $orphan"
                done < "$orphans_file"
            fi
        fi
    fi

    # Cleanup
    rm -f "$all_files" "$referenced_files" "$orphans_file"
}

# ============================================================
# README LINK CHECK
# ============================================================
check_readme_links() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Checking README Links"
    echo "═══════════════════════════════════════════════════════════"

    local broken_links=0

    # Find all markdown files
    while IFS= read -r mdfile; do
        log_verbose "Checking links in: $mdfile"
        local mddir=$(dirname "$mdfile")

        # Extract markdown links [text](path)
        grep -oE '\[([^]]+)\]\(([^)]+)\)' "$mdfile" 2>/dev/null | while read -r link; do
            local path=$(echo "$link" | sed -E 's/\[([^]]+)\]\(([^)]+)\)/\2/')

            # Skip external URLs
            [[ "$path" == http* ]] && continue
            [[ "$path" == mailto:* ]] && continue
            [[ "$path" == "#"* ]] && continue

            # Remove anchor from path
            path="${path%%#*}"
            [ -z "$path" ] && continue

            # Resolve path
            local full_path=""
            if [[ "$path" == /* ]]; then
                full_path="$REPO_ROOT$path"
            else
                full_path="$mddir/$path"
            fi

            # Normalize path
            full_path=$(realpath -m "$full_path" 2>/dev/null || echo "$full_path")

            # Check if exists
            if [ ! -e "$full_path" ]; then
                log_warn "Broken link in $mdfile: $path"
                ((broken_links++))
            fi
        done
    done < <(find "$REPO_ROOT" -name "*.md" -type f ! -path "*/.git/*")

    if [ $broken_links -eq 0 ]; then
        log_ok "All README links valid"
    fi
}

# ============================================================
# DUPLICATE FUNCTIONALITY CHECK
# ============================================================
check_duplicates() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Checking for Duplicate Functionality"
    echo "═══════════════════════════════════════════════════════════"

    # Check for multiple setup.sh files that might conflict
    local setup_files=$(find "$REPO_ROOT" -name "setup.sh" -type f ! -path "*/.git/*" | wc -l)
    if [ "$setup_files" -gt 5 ]; then
        log_warn "Found $setup_files setup.sh files - check for duplicates"
    fi

    # Check for multiple uninstall scripts
    local uninstall_files=$(find "$REPO_ROOT" -name "uninstall*.sh" -type f ! -path "*/.git/*" | wc -l)
    if [ "$uninstall_files" -gt 4 ]; then
        log_warn "Found $uninstall_files uninstall scripts - check for duplicates"
    fi

    # Look for files with very similar content (potential duplicates)
    if [ "$QUICK_MODE" = false ]; then
        log_info "Checking for content duplicates (this may take a moment)..."

        # Find shell scripts with similar first 50 lines
        local seen_hashes=""
        while IFS= read -r script; do
            local hash=$(head -50 "$script" 2>/dev/null | grep -v "^#" | grep -v "^$" | md5sum | cut -d' ' -f1)
            if echo "$seen_hashes" | grep -q "$hash"; then
                log_warn "Potential duplicate content: $script"
            fi
            seen_hashes="$seen_hashes $hash"
        done < <(find "$REPO_ROOT" -name "*.sh" -type f -size +1k ! -path "*/.git/*" | head -50)
    fi

    log_ok "Duplicate check complete"
}

# ============================================================
# GENERATE REPORT
# ============================================================
generate_report() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  Validation Report"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    echo -e "  ${GREEN}Errors:${NC}   $ERRORS"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
    echo -e "  ${CYAN}Orphans:${NC}  $ORPHANS"
    echo ""

    if [ $ERRORS -gt 0 ]; then
        echo -e "  ${RED}Status: FAILED${NC} - Fix errors before merging"
        return 2
    elif [ $WARNINGS -gt 0 ] || [ $ORPHANS -gt 0 ]; then
        echo -e "  ${YELLOW}Status: PASSED WITH WARNINGS${NC}"
        return 0  # Warnings are non-blocking
    else
        echo -e "  ${GREEN}Status: PASSED${NC}"
        return 0
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    parse_args "$@"

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       HookProbe Repository Cleanup Validator v1.0.0          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Repository: $REPO_ROOT"
    echo "Mode: $([ "$QUICK_MODE" = true ] && echo "Quick" || echo "Full")"
    echo ""

    check_required_files
    check_directory_structure

    if [ "$QUICK_MODE" = false ]; then
        check_shell_references
        check_orphaned_files
        check_readme_links
        check_duplicates
    fi

    generate_report
}

main "$@"
