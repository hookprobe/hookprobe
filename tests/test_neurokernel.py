"""
Neuro-Kernel Phase 1 & Phase 2 Tests

Phase 1: Template-based kernel orchestration system
  - Type definitions
  - Template registry matching
  - eBPF compiler static analysis
  - Sandbox testing
  - Sensor manager lifecycle
  - Kernel orchestrator end-to-end
  - Integration with existing AEGIS components

Phase 2: Streaming eBPF-RAG pipeline
  - Event chunker aggregation
  - Embedding engine (hash fallback)
  - Vector store (SQLite brute-force)
  - Streaming RAG pipeline end-to-end
  - Memory integration (recall_streaming_context)
  - Orchestrator LLM context building

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


# ====================================================================
# PHASE 2: STREAMING eBPF-RAG TESTS
# ====================================================================

# ------------------------------------------------------------------
# Event Chunker Tests
# ------------------------------------------------------------------

class TestEventChunker:
    """Test event aggregation into embeddable chunks."""

    def _make_event(self, **kwargs):
        from core.aegis.neurokernel.types import SensorEvent, SensorType
        defaults = dict(
            sensor_type=SensorType.NETWORK,
            timestamp=time.time(),
            source_ip="10.200.0.45",
            dest_ip="192.168.1.1",
            protocol=6,
            port=443,
            payload_len=128,
        )
        defaults.update(kwargs)
        return SensorEvent(**defaults)

    def test_ingest_single_event(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        chunker.ingest(self._make_event())
        stats = chunker.stats()
        assert stats["events_ingested"] == 1
        assert stats["active_buckets"] == 1

    def test_flush_completes_window(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        now = time.time()
        # Event from 2 seconds ago (its window is completed)
        chunker.ingest(self._make_event(timestamp=now - 2.0))
        chunks = chunker.flush(now=now)
        assert len(chunks) == 1
        assert chunks[0].source_ip == "10.200.0.45"
        assert chunks[0].event_type == "network"
        assert chunks[0].raw_count == 1

    def test_flush_keeps_active_windows(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        now = time.time()
        # Event from right now (still active)
        chunker.ingest(self._make_event(timestamp=now))
        chunks = chunker.flush(now=now)
        assert len(chunks) == 0

    def test_flush_all(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        chunker.ingest(self._make_event())
        chunks = chunker.flush_all()
        assert len(chunks) == 1
        assert chunker.stats()["active_buckets"] == 0

    def test_batch_ingest(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        events = [self._make_event() for _ in range(10)]
        chunker.ingest_batch(events)
        assert chunker.stats()["events_ingested"] == 10

    def test_aggregation_by_ip_and_type(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        from core.aegis.neurokernel.types import SensorType
        chunker = EventChunker(window_s=1.0)
        now = time.time() - 2.0

        # Network events from IP A
        for _ in range(5):
            chunker.ingest(self._make_event(
                source_ip="10.0.0.1", timestamp=now, sensor_type=SensorType.NETWORK,
            ))
        # DNS events from IP A
        for _ in range(3):
            chunker.ingest(self._make_event(
                source_ip="10.0.0.1", timestamp=now, sensor_type=SensorType.DNS,
            ))
        # Network events from IP B
        for _ in range(4):
            chunker.ingest(self._make_event(
                source_ip="10.0.0.2", timestamp=now, sensor_type=SensorType.NETWORK,
            ))

        chunks = chunker.flush(now=time.time())
        assert len(chunks) == 3
        ip_types = {(c.source_ip, c.event_type) for c in chunks}
        assert ("10.0.0.1", "network") in ip_types
        assert ("10.0.0.1", "dns") in ip_types
        assert ("10.0.0.2", "network") in ip_types

    def test_summary_generation_network(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        now = time.time() - 2.0
        for i in range(5):
            chunker.ingest(self._make_event(
                timestamp=now, dest_ip=f"192.168.1.{i}", port=80 + i,
            ))
        chunks = chunker.flush(now=time.time())
        assert len(chunks) == 1
        summary = chunks[0].summary
        assert "10.200.0.45" in summary
        assert "5 network events" in summary
        assert "5 unique destination" in summary

    def test_summary_generation_dns(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        from core.aegis.neurokernel.types import SensorType
        chunker = EventChunker(window_s=1.0)
        now = time.time() - 2.0
        chunker.ingest(self._make_event(
            timestamp=now, sensor_type=SensorType.DNS,
            metadata={"domains": ["example.com", "test.com"]},
        ))
        chunks = chunker.flush(now=time.time())
        assert len(chunks) == 1
        assert "DNS" in chunks[0].summary

    def test_chunk_id_format(self):
        from core.aegis.neurokernel.event_chunker import EventChunk
        chunk = EventChunk(
            timestamp=1000.0, source_ip="10.0.0.1",
            event_type="network", summary="test", raw_count=1,
        )
        assert chunk.chunk_id == "10.0.0.1:network:1000"

    def test_metrics_extraction(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        now = time.time() - 2.0
        for i in range(3):
            chunker.ingest(self._make_event(
                timestamp=now, dest_ip=f"10.0.0.{i}", port=80,
                payload_len=1024,
            ))
        chunks = chunker.flush(now=time.time())
        assert len(chunks) == 1
        m = chunks[0].key_metrics
        assert m["event_count"] == 3.0
        assert m["unique_dests"] == 3.0
        assert m["total_bytes"] == 3072.0

    def test_backpressure_evicts_oldest(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        chunker.MAX_BUCKETS = 3

        now = time.time()
        for i in range(5):
            chunker.ingest(self._make_event(
                source_ip=f"10.0.0.{i}", timestamp=now + i * 0.001,
            ))
        # Should have evicted to stay at MAX_BUCKETS
        assert chunker.stats()["active_buckets"] <= 3

    def test_bytes_formatting_in_summary(self):
        from core.aegis.neurokernel.event_chunker import EventChunker
        chunker = EventChunker(window_s=1.0)
        now = time.time() - 2.0
        chunker.ingest(self._make_event(timestamp=now, payload_len=2 * 1024 * 1024))
        chunks = chunker.flush(now=time.time())
        assert "MB" in chunks[0].summary


# ------------------------------------------------------------------
# Embedding Engine Tests
# ------------------------------------------------------------------

class TestEmbeddingEngine:
    """Test the embedding engine with hash fallback."""

    def test_hash_embed_basic(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        vecs = engine.embed(["hello world"])
        assert len(vecs) == 1
        assert len(vecs[0]) == 384
        assert engine.dimension == 384

    def test_hash_embed_deterministic(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        v1 = engine.embed(["test string"])
        v2 = engine.embed(["test string"])
        assert v1[0] == v2[0]

    def test_hash_embed_different_strings(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        v1 = engine.embed(["hello"])[0]
        v2 = engine.embed(["world"])[0]
        # Different strings should produce different vectors
        assert v1 != v2

    def test_embed_single(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        vec = engine.embed_single("test")
        assert len(vec) == 384

    def test_embed_empty_list(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        result = engine.embed([])
        assert result == []

    def test_embed_batch(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        texts = [f"text {i}" for i in range(10)]
        vecs = engine.embed(texts)
        assert len(vecs) == 10
        assert all(len(v) == 384 for v in vecs)

    def test_vectors_are_normalized(self):
        import math
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        vec = engine.embed_single("normalize test")
        norm = math.sqrt(sum(x * x for x in vec))
        assert abs(norm - 1.0) < 0.01  # Should be unit length

    def test_cosine_similarity_identical(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine, cosine_similarity
        engine = EmbeddingEngine(force_hash=True)
        vec = engine.embed_single("identical")
        sim = cosine_similarity(vec, vec)
        assert abs(sim - 1.0) < 0.01

    def test_cosine_similarity_different(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine, cosine_similarity
        engine = EmbeddingEngine(force_hash=True)
        v1 = engine.embed_single("cat")
        v2 = engine.embed_single("supercalifragilisticexpialidocious")
        sim = cosine_similarity(v1, v2)
        # Different strings should have low similarity (hash-based)
        assert sim < 0.9

    def test_stats(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        stats = engine.stats()
        assert stats["using_model"] is False
        assert stats["dimension"] == 384
        assert stats["backend"] == "hash"

    def test_using_model_property(self):
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        engine = EmbeddingEngine(force_hash=True)
        assert engine.using_model is False


# ------------------------------------------------------------------
# Vector Store Tests
# ------------------------------------------------------------------

class TestSQLiteVectorStore:
    """Test the SQLite brute-force vector store."""

    def _make_chunk(self, ip="10.0.0.1", event_type="network", ts=None, embedding=None):
        from core.aegis.neurokernel.event_chunker import EventChunk
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        if ts is None:
            ts = time.time()
        if embedding is None:
            engine = EmbeddingEngine(force_hash=True)
            embedding = engine.embed_single(f"{ip}:{event_type}:{ts}")
        return EventChunk(
            timestamp=ts, source_ip=ip, event_type=event_type,
            summary=f"{ip} generated network events",
            raw_count=10, embedding=embedding,
        )

    def test_upsert_and_count(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        chunks = [self._make_chunk(ip=f"10.0.0.{i}") for i in range(5)]
        stored = store.upsert(chunks)
        assert stored == 5
        assert store.count() == 5

    def test_upsert_empty(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        assert store.upsert([]) == 0

    def test_upsert_skips_no_embedding(self):
        from core.aegis.neurokernel.event_chunker import EventChunk
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        chunk = EventChunk(
            timestamp=time.time(), source_ip="10.0.0.1",
            event_type="network", summary="test", raw_count=1,
            embedding=None,  # No embedding
        )
        stored = store.upsert([chunk])
        assert stored == 0

    def test_search_returns_results(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        store = create_vector_store(backend="sqlite")
        engine = EmbeddingEngine(force_hash=True)

        chunks = [self._make_chunk(ip=f"10.0.0.{i}") for i in range(5)]
        store.upsert(chunks)

        query_vec = engine.embed_single("10.0.0.1 network events")
        results = store.search(query_embedding=query_vec, k=3, time_window_s=60.0)
        assert len(results) <= 3
        assert all(hasattr(r, "summary") for r in results)
        # Results should have similarity scores
        assert all("similarity" in r.key_metrics for r in results)

    def test_search_respects_time_window(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        store = create_vector_store(backend="sqlite")
        engine = EmbeddingEngine(force_hash=True)

        now = time.time()
        # Old chunk (2 minutes ago)
        old = self._make_chunk(ip="10.0.0.1", ts=now - 120)
        # Recent chunk
        recent = self._make_chunk(ip="10.0.0.2", ts=now)
        store.upsert([old, recent])

        query_vec = engine.embed_single("test")
        results = store.search(query_embedding=query_vec, k=10, time_window_s=60.0)
        # Only the recent chunk should be in the results
        assert len(results) == 1
        assert results[0].source_ip == "10.0.0.2"

    def test_evict_older_than(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        now = time.time()
        chunks = [
            self._make_chunk(ip="10.0.0.1", ts=now - 100),
            self._make_chunk(ip="10.0.0.2", ts=now - 50),
            self._make_chunk(ip="10.0.0.3", ts=now),
        ]
        store.upsert(chunks)
        assert store.count() == 3

        evicted = store.evict_older_than(now - 60)
        assert evicted == 1
        assert store.count() == 2

    def test_clear(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        chunks = [self._make_chunk(ip=f"10.0.0.{i}") for i in range(3)]
        store.upsert(chunks)
        assert store.count() == 3
        store.clear()
        assert store.count() == 0

    def test_stats(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        chunks = [self._make_chunk()]
        store.upsert(chunks)
        stats = store.stats()
        assert stats["backend"] == "sqlite"
        assert stats["total_vectors"] == 1
        assert stats["dimension"] == 384

    def test_upsert_replaces_existing(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        store = create_vector_store(backend="sqlite")
        now = time.time()
        c1 = self._make_chunk(ip="10.0.0.1", ts=now)
        store.upsert([c1])
        assert store.count() == 1

        # Same chunk_id (same ip:type:int(ts)) should replace
        c2 = self._make_chunk(ip="10.0.0.1", ts=now)
        store.upsert([c2])
        assert store.count() == 1

    def test_search_empty_store(self):
        from core.aegis.neurokernel.vector_store import create_vector_store
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        store = create_vector_store(backend="sqlite")
        engine = EmbeddingEngine(force_hash=True)
        query_vec = engine.embed_single("test")
        results = store.search(query_embedding=query_vec, k=5)
        assert results == []

    def test_factory_default_sqlite(self):
        from core.aegis.neurokernel.vector_store import create_vector_store, SQLiteVectorStore
        store = create_vector_store()
        assert isinstance(store, SQLiteVectorStore)

    def test_factory_chromadb_fallback(self):
        """When chromadb unavailable, should fall back to SQLite."""
        from core.aegis.neurokernel.vector_store import create_vector_store, SQLiteVectorStore
        # This system likely doesn't have chromadb installed
        store = create_vector_store(backend="chromadb")
        assert isinstance(store, SQLiteVectorStore)


# ------------------------------------------------------------------
# Streaming RAG Pipeline Tests
# ------------------------------------------------------------------

class TestStreamingRAGPipeline:
    """Test the end-to-end streaming RAG pipeline."""

    def _make_event(self, ip="10.200.0.45", ts=None, **kwargs):
        from core.aegis.neurokernel.types import SensorEvent, SensorType
        defaults = dict(
            sensor_type=SensorType.NETWORK,
            timestamp=ts or time.time(),
            source_ip=ip,
            dest_ip="192.168.1.1",
            protocol=6,
            port=443,
            payload_len=128,
        )
        defaults.update(kwargs)
        return SensorEvent(**defaults)

    def test_ingest_single(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        pipeline.ingest(self._make_event())
        stats = pipeline.stats()
        assert stats["events_received"] == 1
        assert stats["buffer_size"] == 1

    def test_ingest_batch(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        events = [self._make_event(ip=f"10.0.0.{i}") for i in range(10)]
        pipeline.ingest_batch(events)
        stats = pipeline.stats()
        assert stats["events_received"] == 10

    def test_tick_processes_events(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        now = time.time()
        # Events from 2 seconds ago (so the chunker window completes)
        for i in range(5):
            pipeline.ingest(self._make_event(ip=f"10.0.0.{i}", ts=now - 2.0))

        pipeline.tick()
        stats = pipeline.stats()
        assert stats["buffer_size"] == 0  # Buffer drained
        assert stats["chunks_embedded"] > 0

    def test_tick_empty_buffer(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        # Should not crash with empty buffer
        pipeline.tick()
        assert pipeline.stats()["chunks_embedded"] == 0

    def test_query_no_events(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        result = pipeline.query("test query")
        assert result == "No recent kernel events found."

    def test_query_with_events(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline(window_s=60.0)
        now = time.time()
        # Ingest events from 2 seconds ago
        for i in range(3):
            pipeline.ingest(self._make_event(ip=f"10.0.0.{i}", ts=now - 2.0))
        pipeline.tick()
        result = pipeline.query("network events")
        assert "Recent Kernel Activity" in result

    def test_query_by_ip(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        now = time.time()
        pipeline.ingest(self._make_event(ip="10.0.0.99", ts=now - 2.0))
        pipeline.tick()
        result = pipeline.query_by_ip("10.0.0.99")
        # Should return something (even if hash-based similarity is imperfect)
        assert isinstance(result, str)

    def test_start_stop_lifecycle(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline(ingest_interval_s=0.1)
        pipeline.start()
        assert pipeline.stats()["running"] is True
        time.sleep(0.2)  # Let the background thread do a tick
        pipeline.stop()
        assert pipeline.stats()["running"] is False

    def test_start_idempotent(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline(ingest_interval_s=0.1)
        pipeline.start()
        pipeline.start()  # Should not create a second thread
        pipeline.stop()

    def test_stop_idempotent(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        pipeline.stop()  # Should not crash when not started
        pipeline.stop()

    def test_eviction(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline(window_s=1.0)
        now = time.time()
        # Old events (10 seconds ago)
        for i in range(3):
            pipeline.ingest(self._make_event(ip=f"10.0.0.{i}", ts=now - 10))
        pipeline.tick()
        initial = pipeline.store.count()
        # Force eviction by calling tick again (eviction checks cutoff)
        pipeline._evict(now)
        assert pipeline.store.count() <= initial

    def test_stats_complete(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        stats = pipeline.stats()
        assert "running" in stats
        assert "events_received" in stats
        assert "chunks_embedded" in stats
        assert "queries_served" in stats
        assert "buffer_size" in stats
        assert "store" in stats
        assert "chunker" in stats
        assert "embedder" in stats

    def test_store_property(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        from core.aegis.neurokernel.vector_store import VectorStore
        pipeline = StreamingRAGPipeline()
        assert isinstance(pipeline.store, VectorStore)

    def test_embedder_property(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        from core.aegis.neurokernel.embedding_engine import EmbeddingEngine
        pipeline = StreamingRAGPipeline()
        assert isinstance(pipeline.embedder, EmbeddingEngine)

    def test_backpressure_limits_chunks(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        pipeline.MAX_CHUNKS_PER_TICK = 2
        now = time.time()
        # Create many events from different IPs (each produces a chunk)
        for i in range(10):
            pipeline.ingest(self._make_event(ip=f"10.0.0.{i}", ts=now - 2.0))
        pipeline.tick()
        # Should have limited to MAX_CHUNKS_PER_TICK
        assert pipeline.stats()["chunks_embedded"] <= 2

    def test_context_formatting(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        from core.aegis.neurokernel.event_chunker import EventChunk
        pipeline = StreamingRAGPipeline()
        chunks = [
            EventChunk(
                timestamp=time.time(),
                source_ip="10.0.0.1",
                event_type="network",
                summary="10.0.0.1 generated 5 events",
                raw_count=5,
                key_metrics={"similarity": 0.95},
            ),
        ]
        result = pipeline._format_context(chunks)
        assert "Recent Kernel Activity (1 events)" in result
        assert "10.0.0.1 generated 5 events" in result
        assert "relevance: 0.95" in result

    def test_format_context_empty(self):
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        result = pipeline._format_context([])
        assert result == "No recent kernel events found."


# ------------------------------------------------------------------
# Memory Integration Tests
# ------------------------------------------------------------------

class TestMemoryStreamingIntegration:
    """Test streaming RAG integration with AEGIS memory."""

    def test_layer_streaming_constant(self):
        from core.aegis.memory import LAYER_STREAMING
        assert LAYER_STREAMING == "streaming"

    def test_recall_streaming_no_pipeline(self):
        from core.aegis.memory import MemoryManager, MemoryConfig
        mm = MemoryManager(MemoryConfig(db_path="/tmp/test_nk_mem_1.db"))
        result = mm.recall_streaming_context("test")
        assert result == ""
        mm.close()
        import os; os.remove("/tmp/test_nk_mem_1.db")

    def test_set_streaming_pipeline(self):
        from core.aegis.memory import MemoryManager, MemoryConfig
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        mm = MemoryManager(MemoryConfig(db_path="/tmp/test_nk_mem_2.db"))
        pipeline = StreamingRAGPipeline()
        mm.set_streaming_pipeline(pipeline)
        result = mm.recall_streaming_context("test")
        assert result == "No recent kernel events found."
        mm.close()
        import os; os.remove("/tmp/test_nk_mem_2.db")

    def test_recall_streaming_with_events(self):
        from core.aegis.memory import MemoryManager, MemoryConfig
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        from core.aegis.neurokernel.types import SensorEvent, SensorType
        mm = MemoryManager(MemoryConfig(db_path="/tmp/test_nk_mem_3.db"))
        pipeline = StreamingRAGPipeline(window_s=60.0)
        mm.set_streaming_pipeline(pipeline)

        now = time.time()
        for i in range(3):
            pipeline.ingest(SensorEvent(
                sensor_type=SensorType.NETWORK,
                timestamp=now - 2.0,
                source_ip=f"10.0.0.{i}",
                dest_ip="192.168.1.1",
                port=443,
                protocol=6,
                payload_len=128,
            ))
        pipeline.tick()

        result = mm.recall_streaming_context("network events")
        assert "Recent Kernel Activity" in result
        mm.close()
        import os; os.remove("/tmp/test_nk_mem_3.db")

    def test_recall_streaming_handles_exception(self):
        """Pipeline query error should return empty string, not raise."""
        from core.aegis.memory import MemoryManager, MemoryConfig
        mm = MemoryManager(MemoryConfig(db_path="/tmp/test_nk_mem_4.db"))

        # Mock pipeline that raises
        broken_pipeline = MagicMock()
        broken_pipeline.query.side_effect = RuntimeError("boom")
        mm.set_streaming_pipeline(broken_pipeline)

        result = mm.recall_streaming_context("test")
        assert result == ""
        mm.close()
        import os; os.remove("/tmp/test_nk_mem_4.db")


# ------------------------------------------------------------------
# Orchestrator LLM Context Tests
# ------------------------------------------------------------------

class TestOrchestratorLLMContext:
    """Test the orchestrator's LLM context building."""

    def _make_signal(self, source="napse", event_type="syn_flood", severity="HIGH", data=None):
        from core.aegis.types import StandardSignal
        return StandardSignal(
            source=source,
            event_type=event_type,
            severity=severity,
            data=data or {},
        )

    def test_build_llm_context_no_rag(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        orch = KernelOrchestrator()
        signal = self._make_signal(data={"source_ip": "10.0.0.1"})
        ctx = orch.build_llm_context(signal)
        assert "napse/syn_flood" in ctx
        assert "10.0.0.1" in ctx

    def test_build_llm_context_with_rag(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        from core.aegis.neurokernel.types import SensorEvent, SensorType

        pipeline = StreamingRAGPipeline(window_s=60.0)
        orch = KernelOrchestrator(rag_pipeline=pipeline)

        now = time.time()
        for i in range(3):
            pipeline.ingest(SensorEvent(
                sensor_type=SensorType.NETWORK,
                timestamp=now - 2.0,
                source_ip=f"10.0.0.{i}",
                dest_ip="192.168.1.1",
                port=443,
                protocol=6,
                payload_len=128,
            ))
        pipeline.tick()

        signal = self._make_signal(data={"source_ip": "10.0.0.1"})
        ctx = orch.build_llm_context(signal)
        assert "napse/syn_flood" in ctx
        assert "Recent Kernel Activity" in ctx

    def test_rag_pipeline_property(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        orch = KernelOrchestrator()
        assert orch.rag_pipeline is None

        pipeline = StreamingRAGPipeline()
        orch.rag_pipeline = pipeline
        assert orch.rag_pipeline is pipeline

    def test_get_status_includes_rag(self):
        from core.aegis.neurokernel.kernel_orchestrator import KernelOrchestrator
        from core.aegis.neurokernel.streaming_rag import StreamingRAGPipeline
        pipeline = StreamingRAGPipeline()
        orch = KernelOrchestrator(rag_pipeline=pipeline)
        status = orch.get_status()
        assert "streaming_rag" in status


# ------------------------------------------------------------------
# Phase 2 Module Exports Tests
# ------------------------------------------------------------------

class TestPhase2Exports:
    """Verify all Phase 2 classes are properly exported."""

    def test_import_event_chunker(self):
        from core.aegis.neurokernel import EventChunk, EventChunker
        assert EventChunk is not None
        assert EventChunker is not None

    def test_import_embedding_engine(self):
        from core.aegis.neurokernel import EmbeddingEngine, cosine_similarity
        assert EmbeddingEngine is not None
        assert cosine_similarity is not None

    def test_import_vector_store(self):
        from core.aegis.neurokernel import VectorStore, SQLiteVectorStore, create_vector_store
        assert VectorStore is not None
        assert SQLiteVectorStore is not None
        assert create_vector_store is not None

    def test_import_streaming_rag(self):
        from core.aegis.neurokernel import StreamingRAGPipeline
        assert StreamingRAGPipeline is not None

    def test_all_exports(self):
        from core.aegis.neurokernel import __all__
        expected = [
            "EventChunk", "EventChunker", "EmbeddingEngine",
            "cosine_similarity", "VectorStore", "SQLiteVectorStore",
            "create_vector_store", "StreamingRAGPipeline",
        ]
        for name in expected:
            assert name in __all__, f"{name} missing from __all__"
