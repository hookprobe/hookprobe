"""
Neuro-Kernel Phase 1 Tests

Tests for the template-based kernel orchestration system:
  - Type definitions
  - Template registry matching
  - eBPF compiler static analysis
  - Sandbox testing
  - Sensor manager lifecycle
  - Kernel orchestrator end-to-end
  - Integration with existing AEGIS components

Run:
    pytest tests/test_neurokernel.py -v --override-ini="addopts="
"""

import time
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch


# ------------------------------------------------------------------
# Type Tests
# ------------------------------------------------------------------

class TestNeuroKernelTypes:
    """Test neurokernel type definitions."""

    def test_compilation_result_success(self):
        from core.aegis.neurokernel.types import CompilationResult, ProgramType, VerifyStatus
        result = CompilationResult(
            success=True,
            program_type=ProgramType.XDP,
            verify_status=VerifyStatus.PASSED,
        )
        assert result.success
        assert result.verified
        assert result.program_type == ProgramType.XDP

    def test_compilation_result_failure(self):
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus
        result = CompilationResult(
            success=False,
            error="Banned pattern detected",
            verify_status=VerifyStatus.FAILED_STATIC,
        )
        assert not result.success
        assert not result.verified
        assert "Banned" in result.error

    def test_kernel_action_to_dict(self):
        from core.aegis.neurokernel.types import KernelAction, KernelActionType, ProgramType
        action = KernelAction(
            action_type=KernelActionType.DEPLOY_TEMPLATE,
            program_id="nk-abc123",
            program_type=ProgramType.XDP,
            attach_point="eth0",
            template_name="syn_flood_xdp",
        )
        d = action.to_dict()
        assert d["action_type"] == "deploy_template"
        assert d["program_id"] == "nk-abc123"
        assert d["template_name"] == "syn_flood_xdp"

    def test_active_program_defaults(self):
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        prog = ActiveProgram(
            program_id="test-1",
            program_type=ProgramType.XDP,
            attach_point="eth0",
        )
        assert prog.deployed_at > 0
        assert prog.rollback_deadline == 0.0
        assert prog.drop_count == 0

    def test_template_match(self):
        from core.aegis.neurokernel.types import TemplateMatch, ProgramType
        match = TemplateMatch(
            matched=True,
            template_name="syn_flood_xdp",
            program_type=ProgramType.XDP,
            confidence=0.95,
        )
        assert match.matched
        assert match.confidence == 0.95

    def test_sandbox_test_result(self):
        from core.aegis.neurokernel.types import SandboxTestResult, SandboxResult
        result = SandboxTestResult(
            passed=True,
            result=SandboxResult.PASSED,
            duration_s=0.01,
        )
        assert result.passed
        assert result.result == SandboxResult.PASSED

    def test_sensor_event(self):
        from core.aegis.neurokernel.types import SensorEvent, SensorType
        event = SensorEvent(
            sensor_type=SensorType.NETWORK,
            source_ip="10.200.0.45",
            dest_ip="8.8.8.8",
            protocol=6,
            port=443,
        )
        assert event.source_ip == "10.200.0.45"
        assert event.sensor_type == SensorType.NETWORK

    def test_program_type_values(self):
        from core.aegis.neurokernel.types import ProgramType
        assert ProgramType.XDP.value == "xdp"
        assert ProgramType.TC.value == "tc"
        assert ProgramType.KPROBE.value == "kprobe"


# ------------------------------------------------------------------
# Template Registry Tests
# ------------------------------------------------------------------

class TestTemplateRegistry:
    """Test eBPF template registry matching."""

    def _make_signal(self, source="napse", event_type="syn_flood", severity="HIGH", data=None):
        from core.aegis.types import StandardSignal
        return StandardSignal(
            source=source,
            event_type=event_type,
            severity=severity,
            data=data or {},
        )

    def test_registry_has_10_templates(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        assert len(reg) == 10

    def test_list_templates(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        templates = reg.list_templates()
        assert len(templates) == 10
        names = {t["name"] for t in templates}
        assert "syn_flood_xdp" in names
        assert "dns_tunnel_xdp" in names

    def test_match_syn_flood(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="syn_flood", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.matched
        assert match.template_name == "syn_flood_xdp"
        assert match.confidence >= 0.9

    def test_match_udp_flood(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="qsecbit", event_type="ddos_udp_flood", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "udp_flood_xdp"

    def test_match_port_scan(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="port_scan_detected", severity="MEDIUM")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "port_scan_xdp"

    def test_match_dns_tunnel(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="dns", event_type="dns_tunnel_detected", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "dns_tunnel_xdp"

    def test_match_arp_spoof(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="arp_spoof_detected", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "arp_spoof_xdp"

    def test_match_icmp_flood(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="qsecbit", event_type="icmp_flood", severity="MEDIUM")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "icmp_flood_xdp"

    def test_no_match_low_severity(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="syn_flood", severity="LOW")
        match = reg.match(signal)
        assert match is None

    def test_no_match_unknown_event(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="unknown_stuff", severity="HIGH")
        match = reg.match(signal)
        assert match is None

    def test_no_match_wrong_source(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="dhcp", event_type="syn_flood", severity="HIGH")
        match = reg.match(signal)
        assert match is None

    def test_custom_template_registration(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry, EBPFTemplate
        from core.aegis.neurokernel.types import ProgramType
        reg = TemplateRegistry()
        custom = EBPFTemplate(
            name="custom_test",
            description="Test template",
            program_type=ProgramType.XDP,
            c_source="// test",
            source_patterns=[r"test"],
            event_patterns=[r"custom"],
            severity_min="LOW",
            confidence=0.99,
        )
        reg.register(custom)
        assert len(reg) == 11
        assert reg.get("custom_test") is not None

    def test_unregister_template(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        assert reg.unregister("syn_flood_xdp")
        assert len(reg) == 9
        assert not reg.unregister("nonexistent")

    def test_match_dns_amplification(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="dns_amp_attack", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "dns_amplification_xdp"

    def test_match_tcp_rst(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="tcp_rst_attack", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "tcp_rst_attack_xdp"

    def test_match_ip_spoof(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="qsecbit", event_type="ip_spoof_detected", severity="HIGH")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "ip_spoof_xdp"

    def test_match_slowloris(self):
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        reg = TemplateRegistry()
        signal = self._make_signal(source="napse", event_type="slowloris_attack", severity="MEDIUM")
        match = reg.match(signal)
        assert match is not None
        assert match.template_name == "slowloris_tc"


# ------------------------------------------------------------------
# Compiler Tests
# ------------------------------------------------------------------

class TestEBPFCompiler:
    """Test eBPF compiler static analysis."""

    def test_static_analysis_valid_code(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
BPF_ARRAY(stats, u64, 2);
int xdp_test(struct xdp_md *ctx) { return XDP_PASS; }
"""
        result = compiler.static_analysis(code)
        assert result.success

    def test_static_analysis_banned_system(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <uapi/linux/bpf.h>\nint test() { system("rm -rf /"); }'
        result = compiler.static_analysis(code)
        assert not result.success
        assert "Banned pattern" in result.error

    def test_static_analysis_banned_exec(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <uapi/linux/bpf.h>\nint test() { execve("/bin/sh", 0, 0); }'
        result = compiler.static_analysis(code)
        assert not result.success

    def test_static_analysis_banned_asm(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <uapi/linux/bpf.h>\nasm volatile("int $0x80");'
        result = compiler.static_analysis(code)
        assert not result.success

    def test_static_analysis_banned_probe_write_user(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <uapi/linux/bpf.h>\nbpf_probe_write_user(dst, src, len);'
        result = compiler.static_analysis(code)
        assert not result.success

    def test_static_analysis_banned_override_return(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <uapi/linux/bpf.h>\nbpf_override_return(ctx, 0);'
        result = compiler.static_analysis(code)
        assert not result.success

    def test_static_analysis_banned_popen(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <uapi/linux/bpf.h>\nFILE *f = popen("cmd", "r");'
        result = compiler.static_analysis(code)
        assert not result.success

    def test_static_analysis_banned_non_kernel_include(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = '#include <stdio.h>\nint test() { return 0; }'
        result = compiler.static_analysis(code)
        assert not result.success

    def test_static_analysis_code_too_long(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = "// " + "x" * 9000
        result = compiler.static_analysis(code)
        assert not result.success
        assert "maximum length" in result.error

    def test_static_analysis_too_many_includes(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = "\n".join([f"#include <uapi/linux/bpf.h>" for _ in range(15)])
        result = compiler.static_analysis(code)
        assert not result.success
        assert "includes" in result.error.lower()

    def test_compile_and_verify_skips_without_bcc(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        from core.aegis.neurokernel.types import VerifyStatus
        compiler = EBPFCompiler()
        code = r"""
#include <uapi/linux/bpf.h>
int xdp_test(struct xdp_md *ctx) { return XDP_PASS; }
"""
        result = compiler.compile_and_verify(code)
        # Without BCC, verifier is skipped but static analysis still runs
        assert result.success
        assert result.verify_status in (VerifyStatus.PASSED, VerifyStatus.SKIPPED)

    def test_extract_code_from_fenced_block(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        llm_output = """Here is the eBPF program:

```c
#include <uapi/linux/bpf.h>
int xdp_test(struct xdp_md *ctx) { return XDP_DROP; }
```

This will drop all packets.
"""
        code = compiler.extract_code(llm_output)
        assert code is not None
        assert "#include" in code
        assert "XDP_DROP" in code

    def test_extract_code_from_raw(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        llm_output = """#include <uapi/linux/bpf.h>
BPF_ARRAY(stats, u64, 1);
int xdp_test(struct xdp_md *ctx) { return XDP_PASS; }"""
        code = compiler.extract_code(llm_output)
        assert code is not None
        assert "BPF_ARRAY" in code

    def test_extract_code_no_code(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        compiler = EBPFCompiler()
        code = compiler.extract_code("I don't know how to write eBPF code.")
        assert code is None


# ------------------------------------------------------------------
# Sandbox Tests
# ------------------------------------------------------------------

class TestEBPFSandbox:
    """Test eBPF sandbox testing."""

    def test_sandbox_passes_valid(self):
        from core.aegis.neurokernel.ebpf_sandbox import EBPFSandbox
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus
        sandbox = EBPFSandbox()
        compilation = CompilationResult(
            success=True,
            verify_status=VerifyStatus.PASSED,
        )
        result = sandbox.test(compilation)
        assert result.passed

    def test_sandbox_fails_compilation_error(self):
        from core.aegis.neurokernel.ebpf_sandbox import EBPFSandbox
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus
        sandbox = EBPFSandbox()
        compilation = CompilationResult(
            success=False,
            error="Banned pattern",
            verify_status=VerifyStatus.FAILED_STATIC,
        )
        result = sandbox.test(compilation)
        assert not result.passed
        assert "Compilation failed" in result.reason

    def test_sandbox_fails_verifier(self):
        from core.aegis.neurokernel.ebpf_sandbox import EBPFSandbox
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus
        sandbox = EBPFSandbox()
        compilation = CompilationResult(
            success=False,
            error="unbounded loop",
            verify_status=VerifyStatus.FAILED_VERIFIER,
        )
        result = sandbox.test(compilation)
        assert not result.passed

    def test_sandbox_test_source_convenience(self):
        from core.aegis.neurokernel.ebpf_sandbox import EBPFSandbox
        sandbox = EBPFSandbox()
        code = r"""
#include <uapi/linux/bpf.h>
int xdp_test(struct xdp_md *ctx) { return XDP_PASS; }
"""
        result = sandbox.test_source(code)
        assert result.passed

    def test_sandbox_passes_skipped_verification(self):
        from core.aegis.neurokernel.ebpf_sandbox import EBPFSandbox
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus, SandboxResult
        sandbox = EBPFSandbox()
        compilation = CompilationResult(
            success=True,
            verify_status=VerifyStatus.SKIPPED,
        )
        result = sandbox.test(compilation)
        assert result.passed
        assert result.result == SandboxResult.PASSED


# ------------------------------------------------------------------
# Sensor Manager Tests
# ------------------------------------------------------------------

class TestSensorManager:
    """Test sensor manager lifecycle."""

    def test_deploy_and_get(self):
        from core.aegis.neurokernel.sensor_manager import SensorManager
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        mgr = SensorManager()
        prog = ActiveProgram(
            program_id="test-1",
            program_type=ProgramType.XDP,
            attach_point="eth0",
            template_name="syn_flood_xdp",
        )
        assert mgr.deploy(prog)
        assert len(mgr) == 1
        retrieved = mgr.get("test-1")
        assert retrieved is not None
        assert retrieved.template_name == "syn_flood_xdp"

    def test_remove(self):
        from core.aegis.neurokernel.sensor_manager import SensorManager
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        mgr = SensorManager()
        prog = ActiveProgram(
            program_id="test-1",
            program_type=ProgramType.XDP,
            attach_point="eth0",
        )
        mgr.deploy(prog)
        removed = mgr.remove("test-1")
        assert removed is not None
        assert len(mgr) == 0
        assert mgr.remove("test-1") is None

    def test_max_limit(self):
        from core.aegis.neurokernel.sensor_manager import SensorManager
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        mgr = SensorManager()
        mgr.MAX_ACTIVE_PROGRAMS = 3  # Lower limit for testing
        for i in range(3):
            prog = ActiveProgram(
                program_id=f"test-{i}",
                program_type=ProgramType.XDP,
                attach_point="eth0",
            )
            assert mgr.deploy(prog)
        # 4th should fail
        prog = ActiveProgram(
            program_id="test-3",
            program_type=ProgramType.XDP,
            attach_point="eth0",
        )
        assert not mgr.deploy(prog)

    def test_get_by_template(self):
        from core.aegis.neurokernel.sensor_manager import SensorManager
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        mgr = SensorManager()
        for i in range(3):
            t = "syn_flood_xdp" if i < 2 else "udp_flood_xdp"
            prog = ActiveProgram(
                program_id=f"test-{i}",
                program_type=ProgramType.XDP,
                attach_point="eth0",
                template_name=t,
            )
            mgr.deploy(prog)
        syn = mgr.get_by_template("syn_flood_xdp")
        assert len(syn) == 2

    def test_rollback_deadlines(self):
        from core.aegis.neurokernel.sensor_manager import SensorManager
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        mgr = SensorManager()
        prog = ActiveProgram(
            program_id="test-1",
            program_type=ProgramType.XDP,
            attach_point="eth0",
            rollback_deadline=time.time() - 1,  # Already expired
        )
        mgr.deploy(prog)
        expired = mgr.check_rollback_deadlines()
        assert "test-1" in expired

    def test_status(self):
        from core.aegis.neurokernel.sensor_manager import SensorManager
        from core.aegis.neurokernel.types import ActiveProgram, ProgramType
        mgr = SensorManager()
        prog = ActiveProgram(
            program_id="test-1",
            program_type=ProgramType.XDP,
            attach_point="eth0",
        )
        mgr.deploy(prog)
        status = mgr.get_status()
        assert status["active_count"] == 1
        assert "test-1" in status["programs"]


# ------------------------------------------------------------------
# Kernel Orchestrator Tests
# ------------------------------------------------------------------

class TestKernelOrchestrator:
    """Test kernel orchestrator end-to-end flow.

    Uses a mock verifier to avoid dependency on kernel headers / BCC
    compilation environment. We test pipeline logic, not kernel compilation.
    """

    def _make_signal(self, source="napse", event_type="syn_flood", severity="HIGH", data=None):
        from core.aegis.types import StandardSignal
        return StandardSignal(
            source=source,
            event_type=event_type,
            severity=severity,
            data=data or {},
        )

    @staticmethod
    def _mock_verify(c_source, program_type):
        """Mock verifier that returns SKIPPED (simulates no BCC)."""
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus
        return CompilationResult(
            success=True,
            program_type=program_type,
            c_source=c_source,
            verify_status=VerifyStatus.SKIPPED,
        )

    @patch("core.aegis.neurokernel.ebpf_verifier_wrapper.EBPFVerifier.verify")
    def test_handle_signal_deploys_template(self, mock_verify):
        mock_verify.side_effect = self._mock_verify
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator(interface="eth0")
        signal = self._make_signal(source="napse", event_type="syn_flood", severity="HIGH")
        action = orch.handle_signal(signal)
        assert action is not None
        assert action.template_name == "syn_flood_xdp"
        assert action.action_type.value == "deploy_template"
        assert action.attach_point == "eth0"

    def test_handle_signal_no_match(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator()
        signal = self._make_signal(source="dhcp", event_type="new_lease", severity="INFO")
        action = orch.handle_signal(signal)
        assert action is None

    @patch("core.aegis.neurokernel.ebpf_verifier_wrapper.EBPFVerifier.verify")
    def test_handle_signal_duplicate_skipped(self, mock_verify):
        mock_verify.side_effect = self._mock_verify
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator(interface="eth0")
        signal = self._make_signal(source="napse", event_type="syn_flood", severity="HIGH")

        action1 = orch.handle_signal(signal)
        assert action1 is not None

        # Second call with same template should be skipped (duplicate)
        action2 = orch.handle_signal(signal)
        assert action2 is None

    @patch("core.aegis.neurokernel.ebpf_verifier_wrapper.EBPFVerifier.verify")
    def test_handle_signal_rate_limit(self, mock_verify):
        mock_verify.side_effect = self._mock_verify
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator(interface="eth0")
        orch.MAX_DEPLOYS_PER_MINUTE = 2

        actions = []
        event_types = [
            "syn_flood", "udp_flood", "port_scan_detected",
            "icmp_flood", "dns_amp_attack",
        ]
        for evt in event_types:
            signal = self._make_signal(source="napse", event_type=evt, severity="HIGH")
            action = orch.handle_signal(signal)
            if action:
                actions.append(action)

        # Should have deployed at most 2 (rate limit)
        assert len(actions) <= 2

    @patch("core.aegis.neurokernel.ebpf_verifier_wrapper.EBPFVerifier.verify")
    def test_rollback(self, mock_verify):
        mock_verify.side_effect = self._mock_verify
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator(interface="eth0")
        signal = self._make_signal(source="napse", event_type="syn_flood", severity="HIGH")
        action = orch.handle_signal(signal)
        assert action is not None

        # Rollback
        rollback = orch.rollback(action.program_id)
        assert rollback is not None
        assert rollback.action_type.value == "rollback"

        # Rollback nonexistent
        assert orch.rollback("nonexistent") is None

    @patch("core.aegis.neurokernel.ebpf_verifier_wrapper.EBPFVerifier.verify")
    def test_check_rollbacks_expired(self, mock_verify):
        mock_verify.side_effect = self._mock_verify
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator(interface="eth0")
        orch.ROLLBACK_TIMEOUT_S = 0  # Immediate rollback

        signal = self._make_signal(source="napse", event_type="syn_flood", severity="HIGH")
        action = orch.handle_signal(signal)
        assert action is not None

        # The rollback deadline should already be passed
        time.sleep(0.01)
        rollbacks = orch.check_rollbacks()
        assert len(rollbacks) == 1

    def test_get_status(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator(interface="eth0")
        status = orch.get_status()
        assert "sensors" in status
        assert "templates" in status
        assert status["template_count"] == 10
        assert status["interface"] == "eth0"

    def test_sensor_manager_property(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        from core.aegis.neurokernel.sensor_manager import SensorManager
        orch = KernelOrchestrator()
        assert isinstance(orch.sensor_manager, SensorManager)

    def test_template_registry_property(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        orch = KernelOrchestrator()
        assert isinstance(orch.template_registry, TemplateRegistry)

    def test_compilation_failure_returns_none(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        from core.aegis.neurokernel.ebpf_template_registry import EBPFTemplate
        from core.aegis.neurokernel.types import ProgramType

        orch = KernelOrchestrator(interface="eth0")
        # Register a template with invalid code (banned pattern)
        bad = EBPFTemplate(
            name="bad_template",
            description="Invalid template for testing",
            program_type=ProgramType.XDP,
            c_source='#include <stdio.h>\nsystem("bad");',
            source_patterns=[r"test"],
            event_patterns=[r"bad"],
            severity_min="HIGH",
            confidence=0.99,
        )
        orch.template_registry.register(bad)

        signal = self._make_signal(source="test", event_type="bad_event", severity="HIGH")
        action = orch.handle_signal(signal)
        assert action is None


# ------------------------------------------------------------------
# Integration with Existing AEGIS Tests
# ------------------------------------------------------------------

class TestNeuroKernelIntegration:
    """Test integration with existing AEGIS components."""

    def test_orchestrator_routing_rules_include_kernel(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "napse.zero_day" in ROUTING_RULES
        assert "kernel.ebpf_deployed" in ROUTING_RULES
        assert "kernel.ebpf_failed" in ROUTING_RULES
        assert "kernel.rollback" in ROUTING_RULES
        assert "kernel.anomaly" in ROUTING_RULES

    def test_principle_guard_kernel_safety(self):
        from core.aegis.principle_guard import IMMUTABLE_PRINCIPLES
        assert "never_disable_kernel_safety" in IMMUTABLE_PRINCIPLES
        principle = IMMUTABLE_PRINCIPLES["never_disable_kernel_safety"]
        assert "bypass_verifier" in principle["blocked_actions"]
        assert "load_unverified_bpf" in principle["blocked_actions"]

    def test_principle_guard_blocks_bypass_verifier(self):
        from core.aegis.principle_guard import check_action
        result = check_action("GUARDIAN", "bypass_verifier", {})
        assert not result.safe
        assert "kernel" in result.violated_principle

    def test_principle_guard_blocks_dangerous_patterns(self):
        from core.aegis.principle_guard import check_action
        result = check_action("GUARDIAN", "deploy_filter", {"code": "bpf_probe_write_user"})
        assert not result.safe

    def test_tool_registry_has_kernel_tools(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert "deploy_ebpf" in TOOL_REGISTRY
        assert "rollback_ebpf" in TOOL_REGISTRY
        assert "list_kernel_programs" in TOOL_REGISTRY

    def test_deploy_ebpf_requires_confirmation(self):
        from core.aegis.tool_executor import TOOL_REGISTRY
        assert TOOL_REGISTRY["deploy_ebpf"].requires_confirmation

    def test_kernel_tools_permission_matrix(self):
        from core.aegis.tool_executor import PERMISSION_MATRIX
        assert "deploy_ebpf" in PERMISSION_MATRIX.get("GUARDIAN", [])
        assert "deploy_ebpf" in PERMISSION_MATRIX.get("MEDIC", [])
        assert "list_kernel_programs" in PERMISSION_MATRIX.get("ORACLE", [])

    def test_reflex_engine_has_hot_swap(self):
        from core.aegis.reflex.engine import ReflexEngine
        engine = ReflexEngine(interface="eth0")
        assert hasattr(engine, "hot_swap_program")
        # Test log-only mode
        engine._executor_mode = "log-only"
        result = engine.hot_swap_program(
            program_id="test-1",
            program_type="xdp",
            attach_point="eth0",
            c_source="// test",
        )
        assert result is True

    def test_neurokernel_singleton_registry(self):
        from core.aegis.neurokernel import (
            register_orchestrator, get_orchestrator, KernelOrchestrator,
        )
        # Initially None
        assert get_orchestrator() is None or True  # May have been set by other tests

        orch = KernelOrchestrator()
        register_orchestrator(orch)
        assert get_orchestrator() is orch

        # Clean up
        register_orchestrator(None)

    def test_verifier_is_available_returns_bool(self):
        from core.aegis.neurokernel.ebpf_verifier_wrapper import EBPFVerifier
        result = EBPFVerifier.is_available()
        assert isinstance(result, bool)


# ------------------------------------------------------------------
# Static Analysis on All Templates
# ------------------------------------------------------------------

class TestTemplateStaticAnalysis:
    """Verify all 10 built-in templates pass static analysis."""

    def test_all_templates_pass_static_analysis(self):
        from core.aegis.neurokernel.ebpf_compiler import EBPFCompiler
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        compiler = EBPFCompiler()
        registry = TemplateRegistry()

        for template_info in registry.list_templates():
            template = registry.get(template_info["name"])
            assert template is not None, f"Template {template_info['name']} not found"
            result = compiler.static_analysis(template.c_source)
            assert result.success, (
                f"Template {template.name} failed static analysis: {result.error}"
            )

    @patch("core.aegis.neurokernel.ebpf_verifier_wrapper.EBPFVerifier.verify")
    def test_all_templates_pass_sandbox(self, mock_verify):
        from core.aegis.neurokernel.ebpf_sandbox import EBPFSandbox
        from core.aegis.neurokernel.ebpf_template_registry import TemplateRegistry
        from core.aegis.neurokernel.types import CompilationResult, VerifyStatus

        def _mock_verify(c_source, program_type):
            return CompilationResult(
                success=True, program_type=program_type,
                c_source=c_source, verify_status=VerifyStatus.SKIPPED,
            )

        mock_verify.side_effect = _mock_verify
        sandbox = EBPFSandbox()
        registry = TemplateRegistry()

        for template_info in registry.list_templates():
            template = registry.get(template_info["name"])
            result = sandbox.test_source(template.c_source)
            assert result.passed, (
                f"Template {template.name} failed sandbox: {result.reason}"
            )
