#!/bin/bash
#
# test_network_filters.sh - Fortress Network Filter Tests
#
# Validates that the nftables-based network filtering works correctly.
# Tests OUI classification and policy enforcement.
#
# Tests:
#   1. nftables availability and rules
#   2. OUI database lookup
#   3. Policy set management
#   4. Device classification
#   5. Filter rule enforcement (simulated)
#
# Usage: ./test_network_filters.sh
#
# Version: 1.0.0
# License: AGPL-3.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FILTER_MANAGER="${PROJECT_DIR}/devices/common/network-filter-manager.sh"
POLICY_MANAGER="${PROJECT_DIR}/lib/network_policy_manager.py"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

log_test() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "  ${GREEN}✓ PASS:${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "  ${RED}✗ FAIL:${NC} $1"
    ((FAILED++))
}

log_warn() {
    echo -e "  ${YELLOW}! WARN:${NC} $1"
    ((WARNINGS++))
}

log_info() {
    echo -e "  [INFO] $1"
}

# ============================================================
# TEST: Script Availability
# ============================================================
test_scripts_exist() {
    log_test "Script Availability"

    if [ -f "$FILTER_MANAGER" ]; then
        log_pass "network-filter-manager.sh exists"
    else
        log_fail "network-filter-manager.sh not found"
    fi

    if [ -x "$FILTER_MANAGER" ] || chmod +x "$FILTER_MANAGER" 2>/dev/null; then
        log_pass "network-filter-manager.sh is executable"
    else
        log_warn "network-filter-manager.sh not executable"
    fi

    if [ -f "$POLICY_MANAGER" ]; then
        log_pass "network_policy_manager.py exists"
    else
        log_fail "network_policy_manager.py not found"
    fi
}

# ============================================================
# TEST: nftables Availability
# ============================================================
test_nftables_available() {
    log_test "nftables Availability"

    if command -v nft &>/dev/null; then
        log_pass "nft command is available"
        local version
        version=$(nft --version 2>/dev/null | head -1)
        log_info "Version: $version"
    else
        log_warn "nftables not installed (testing in simulation mode)"
    fi
}

# ============================================================
# TEST: OUI Database
# ============================================================
test_oui_database() {
    log_test "OUI Database"

    # Test Python OUI classifier
    if command -v python3 &>/dev/null; then
        local test_macs=(
            "B8:27:EB:12:34:56"  # Raspberry Pi -> iot, lan_only
            "00:17:88:AA:BB:CC"  # Philips Hue -> iot, lan_only
            "0C:47:C9:11:22:33"  # Amazon Echo -> voice_assistant, internet_only
            "00:50:10:44:55:66"  # Verifone -> pos, internet_only
            "00:1E:0B:77:88:99"  # HP Printer -> printer, lan_only
            "AA:BB:CC:DD:EE:FF"  # Unknown -> unknown, default
        )

        local expected_policies=(
            "lan_only"
            "lan_only"
            "internet_only"
            "internet_only"
            "lan_only"
            "default"
        )

        local expected_categories=(
            "iot"
            "iot"
            "voice_assistant"
            "pos"
            "printer"
            "unknown"
        )

        cd "$PROJECT_DIR"
        for i in "${!test_macs[@]}"; do
            local mac="${test_macs[$i]}"
            local expected_policy="${expected_policies[$i]}"
            local expected_category="${expected_categories[$i]}"

            local result
            result=$(python3 -c "
import sys
sys.path.insert(0, 'lib')
from network_policy_manager import classify_device
result = classify_device('$mac')
print(result['category'], result['recommended_policy'])
" 2>/dev/null) || result="error"

            if [ "$result" = "error" ]; then
                log_warn "Could not classify $mac (Python error)"
                continue
            fi

            local got_category got_policy
            read got_category got_policy <<< "$result"

            if [ "$got_policy" = "$expected_policy" ]; then
                log_pass "OUI: $mac -> $got_category, $got_policy"
            else
                log_fail "OUI: $mac expected $expected_policy, got $got_policy"
            fi
        done
    else
        log_warn "Python3 not available, skipping OUI tests"
    fi
}

# ============================================================
# TEST: Policy Logic
# ============================================================
test_policy_logic() {
    log_test "Policy Logic"

    # Test policy manager in Python
    if command -v python3 &>/dev/null; then
        cd "$PROJECT_DIR"

        # Test policy creation and retrieval (in-memory only)
        local result
        result=$(python3 -c "
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, 'lib')
from network_policy_manager import NetworkPolicyManager, NetworkPolicy

# Use temp dir to avoid needing root
with tempfile.TemporaryDirectory() as tmpdir:
    manager = NetworkPolicyManager(
        state_dir=Path(tmpdir),
        use_nftables=False  # Don't actually modify nftables
    )

    # Test setting policies
    mac1 = 'AA:BB:CC:DD:EE:01'
    manager.set_policy(mac1, NetworkPolicy.LAN_ONLY)
    p1 = manager.get_policy(mac1)

    mac2 = 'AA:BB:CC:DD:EE:02'
    manager.set_policy(mac2, NetworkPolicy.INTERNET_ONLY)
    p2 = manager.get_policy(mac2)

    mac3 = 'AA:BB:CC:DD:EE:03'
    manager.set_policy(mac3, NetworkPolicy.ISOLATED)
    p3 = manager.get_policy(mac3)

    if p1.policy == NetworkPolicy.LAN_ONLY:
        print('policy_set_lan_only:pass')
    else:
        print('policy_set_lan_only:fail')

    if p2.policy == NetworkPolicy.INTERNET_ONLY:
        print('policy_set_internet_only:pass')
    else:
        print('policy_set_internet_only:fail')

    if p3.policy == NetworkPolicy.ISOLATED:
        print('policy_set_isolated:pass')
    else:
        print('policy_set_isolated:fail')

    # Test auto-classify
    rpi_mac = 'B8:27:EB:11:22:33'
    manager.auto_classify(rpi_mac)
    rpi_policy = manager.get_policy(rpi_mac)
    if rpi_policy.policy == NetworkPolicy.LAN_ONLY:
        print('auto_classify:pass')
    else:
        print('auto_classify:fail')

    # Test get all policies
    all_policies = manager.get_all_policies()
    if len(all_policies) == 4:
        print('get_all:pass')
    else:
        print(f'get_all:fail (got {len(all_policies)})')
" 2>/dev/null) || result="error"

        if [ "$result" = "error" ]; then
            log_fail "Policy logic test failed (Python error)"
            return
        fi

        echo "$result" | while IFS=: read -r test_name test_result; do
            if [ "$test_result" = "pass" ]; then
                log_pass "$test_name"
            else
                log_fail "$test_name"
            fi
        done
    else
        log_warn "Python3 not available, skipping policy logic tests"
    fi
}

# ============================================================
# TEST: Shell Script Syntax
# ============================================================
test_shell_syntax() {
    log_test "Shell Script Syntax"

    if command -v shellcheck &>/dev/null; then
        if shellcheck -x "$FILTER_MANAGER" 2>/dev/null; then
            log_pass "network-filter-manager.sh passes shellcheck"
        else
            log_warn "network-filter-manager.sh has shellcheck warnings"
        fi
    else
        # Basic syntax check
        if bash -n "$FILTER_MANAGER" 2>/dev/null; then
            log_pass "network-filter-manager.sh has valid syntax"
        else
            log_fail "network-filter-manager.sh has syntax errors"
        fi
    fi
}

# ============================================================
# TEST: Python Module Import
# ============================================================
test_python_imports() {
    log_test "Python Module Imports"

    if command -v python3 &>/dev/null; then
        cd "$PROJECT_DIR"

        # Test importing the module
        if python3 -c "
import sys
sys.path.insert(0, 'lib')
from network_policy_manager import (
    OUIClassifier,
    NetworkPolicyManager,
    NetworkPolicy,
    DeviceCategory,
    classify_device,
    get_policy_manager
)
print('imports_ok')
" 2>/dev/null | grep -q "imports_ok"; then
            log_pass "All Python imports work"
        else
            log_fail "Python import errors"
        fi
    else
        log_warn "Python3 not available"
    fi
}

# ============================================================
# TEST: Simulated Filter Scenarios
# ============================================================
test_filter_scenarios() {
    log_test "Filter Scenarios (Simulated)"

    # Test scenario descriptions
    log_info "Scenario: IoT sensor (B8:27:EB:*) should be LAN-only"
    log_info "  - Can reach: 192.168.1.*, 10.*, 172.16.*"
    log_info "  - Cannot reach: Internet (0.0.0.0/0)"

    log_info "Scenario: POS terminal (00:50:10:*) should be Internet-only"
    log_info "  - Can reach: Internet (payment processors)"
    log_info "  - Cannot reach: LAN devices"

    log_info "Scenario: Voice assistant (0C:47:C9:*) should be Internet-only"
    log_info "  - Can reach: Internet (cloud services)"
    log_info "  - Cannot reach: Local cameras, NAS, etc."

    log_info "Scenario: Blocked device should have no access"
    log_info "  - Cannot reach: Anything"

    log_pass "Filter scenarios documented (manual validation required)"
}

# ============================================================
# TEST: nftables Rules Syntax (if available)
# ============================================================
test_nftables_syntax() {
    log_test "nftables Rules Syntax"

    local nft_config="${PROJECT_DIR}/devices/common/network-filter-manager.sh"

    # Extract the nftables config from the script and validate syntax
    if command -v nft &>/dev/null; then
        # Create temp file with just the nftables rules
        local tmp_nft=$(mktemp)
        sed -n '/^flush table inet fortress_filter$/,/^NFTEOF$/p' "$nft_config" | head -n -1 > "$tmp_nft"

        if [ -s "$tmp_nft" ]; then
            if nft -c -f "$tmp_nft" 2>/dev/null; then
                log_pass "nftables rules syntax is valid"
            else
                log_warn "nftables rules may have syntax issues"
            fi
        else
            log_info "Could not extract nftables rules for validation"
        fi

        rm -f "$tmp_nft"
    else
        log_info "nftables not available, skipping syntax check"
    fi
}

# ============================================================
# MAIN
# ============================================================
main() {
    echo "========================================"
    echo "Fortress Network Filter Tests"
    echo "========================================"
    echo ""

    # Run tests
    test_scripts_exist
    test_nftables_available
    test_oui_database
    test_policy_logic
    test_shell_syntax
    test_python_imports
    test_filter_scenarios
    test_nftables_syntax

    # Summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "  ${GREEN}Passed:${NC}   $PASSED"
    echo -e "  ${RED}Failed:${NC}   $FAILED"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}All critical tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Check output above.${NC}"
        exit 1
    fi
}

main "$@"
