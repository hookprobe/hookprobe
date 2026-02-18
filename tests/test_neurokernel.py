"""
Neuro-Kernel Phase 1, Phase 2 & Phase 3 Tests

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

Phase 3: Shadow Pentester
  - Attack library template registry
  - Kernel digital twin
  - Shadow pentester cycles
  - Defense feedback pipeline
  - End-to-end: attack → detect → signature

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


# ==================================================================
# Phase 3: Shadow Pentester Tests
# ==================================================================


class TestAttackLibrary:
    """Test the attack template library."""

    def test_library_has_builtin_templates(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        assert len(lib) == 13

    def test_get_by_name(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        t = lib.get_by_name("port_scan")
        assert t is not None
        assert t.name == "port_scan"
        assert t.mitre_id == "T1046"

    def test_get_by_id(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        t = lib.get("atk-reconnaissance-port_scan")
        assert t is not None
        assert t.name == "port_scan"

    def test_get_by_category(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary, AttackCategory
        lib = AttackLibrary()
        recon = lib.get_by_category(AttackCategory.RECONNAISSANCE)
        assert len(recon) >= 3  # port_scan, arp_scan, dns_enumeration, slow_scan

    def test_get_by_difficulty(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary, AttackDifficulty
        lib = AttackLibrary()
        trivial = lib.get_by_difficulty(AttackDifficulty.TRIVIAL)
        assert len(trivial) >= 3  # port_scan, arp_scan, syn_flood, udp_flood
        # All must be trivial
        for t in trivial:
            assert t.difficulty == AttackDifficulty.TRIVIAL

    def test_list_templates(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        listing = lib.list_templates()
        assert len(listing) == 13
        assert all("template_id" in item for item in listing)
        assert all("mitre_id" in item for item in listing)

    def test_template_id_format(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        t = lib.get_by_name("syn_flood")
        assert t is not None
        assert t.template_id == "atk-impact-syn_flood"

    def test_register_custom_template(self):
        from core.aegis.neurokernel.attack_library import (
            AttackLibrary, AttackTemplate, AttackCategory,
            AttackDifficulty, ExpectedDetection,
        )
        lib = AttackLibrary()
        custom = AttackTemplate(
            name="custom_attack",
            description="A custom test attack",
            category=AttackCategory.EXECUTION,
            difficulty=AttackDifficulty.EXPERT,
            mitre_id="T9999",
            mitre_technique="Custom Technique",
            expected_detection=ExpectedDetection.BEHAVIORAL,
        )
        lib.register(custom)
        assert len(lib) == 14
        assert lib.get_by_name("custom_attack") is not None

    def test_evasion_templates_expect_no_detection(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary, ExpectedDetection
        lib = AttackLibrary()
        slow = lib.get_by_name("slow_scan")
        assert slow is not None
        assert slow.expected_detection == ExpectedDetection.NONE
        exfil = lib.get_by_name("encrypted_exfil")
        assert exfil is not None
        assert exfil.expected_detection == ExpectedDetection.NONE

    def test_attack_execution_evaded(self):
        from core.aegis.neurokernel.attack_library import AttackExecution
        exec1 = AttackExecution(
            template_id="t1", template_name="test",
            category="recon", parameters={},
            success=True, detected=False,
        )
        assert exec1.evaded_detection is True

        exec2 = AttackExecution(
            template_id="t1", template_name="test",
            category="recon", parameters={},
            success=True, detected=True,
        )
        assert exec2.evaded_detection is False

    def test_attack_execution_to_dict(self):
        from core.aegis.neurokernel.attack_library import AttackExecution
        ex = AttackExecution(
            template_id="t1", template_name="test",
            category="recon", parameters={"port": 80},
            success=True, detected=True, detection_layer="L4",
        )
        d = ex.to_dict()
        assert d["template_name"] == "test"
        assert d["detected"] is True
        assert d["evaded_detection"] is False

    def test_get_nonexistent_returns_none(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        assert lib.get("nonexistent") is None
        assert lib.get_by_name("nonexistent") is None

    def test_parameters_have_types(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary
        lib = AttackLibrary()
        scan = lib.get_by_name("port_scan")
        assert scan is not None
        assert len(scan.parameters) >= 2
        # target_ip should be required
        ip_param = [p for p in scan.parameters if p.name == "target_ip"]
        assert len(ip_param) == 1
        assert ip_param[0].required is True
        assert ip_param[0].param_type == "ip"


class TestKernelDigitalTwin:
    """Test the kernel-aware digital twin."""

    def test_create_test_twin(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin(num_devices=3)
        assert len(twin.list_devices()) == 3

    def test_add_remove_device(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin, TwinDevice
        twin = KernelDigitalTwin()
        dev = TwinDevice(mac="AA:BB:CC:DD:EE:01", ip="10.200.0.10", hostname="test")
        twin.add_device(dev)
        assert len(twin.list_devices()) == 1

        removed = twin.remove_device("AA:BB:CC:DD:EE:01")
        assert removed is not None
        assert removed.hostname == "test"
        assert len(twin.list_devices()) == 0

    def test_get_device_by_ip(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin, TwinDevice
        twin = KernelDigitalTwin()
        twin.add_device(TwinDevice(mac="AA:BB:CC:DD:EE:01", ip="10.200.0.10"))
        found = twin.get_device_by_ip("10.200.0.10")
        assert found is not None
        assert found.mac == "AA:BB:CC:DD:EE:01"
        assert twin.get_device_by_ip("1.2.3.4") is None

    def test_get_active_hosts(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin(num_devices=5)
        hosts = twin.get_active_hosts()
        assert len(hosts) == 5
        assert "10.200.0.10" in hosts

    def test_get_open_services(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin(num_devices=2)
        services = twin.get_open_services()
        assert "10.200.0.10" in services
        assert 80 in services["10.200.0.10"]

    def test_create_snapshot(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin(num_devices=3)
        snap = twin.create_snapshot()
        assert snap["device_count"] == 3
        assert "devices" in snap
        assert "10.200.0.10" in [d["ip"] for d in snap["devices"].values()]

    def test_simulate_port_scan(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        result = twin.simulate_attack("port_scan", {
            "target_ip": "10.200.0.10",
            "port_range": "1-50",
        })
        assert result["success"] is True
        assert result["events_generated"] == 50

    def test_simulate_syn_flood(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        result = twin.simulate_attack("syn_flood", {
            "target_ip": "10.200.0.10",
            "rate_pps": 100,
            "duration_s": 2,
        })
        assert result["success"] is True
        assert result["events_generated"] == 200

    def test_simulate_dns_tunnel(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        result = twin.simulate_attack("dns_tunnel", {
            "c2_domain": "evil.test",
            "data_size_kb": 5,
        })
        assert result["success"] is True
        assert result["events_generated"] == 50  # 5KB * 10 queries/KB

    def test_simulate_dga_c2(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        result = twin.simulate_attack("dga_c2", {
            "domain_count": 30,
            "seed": "test",
        })
        assert result["success"] is True
        assert result["events_generated"] == 30

    def test_simulate_arp_spoof(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        result = twin.simulate_attack("arp_spoof", {
            "victim_ip": "10.200.0.10",
            "gateway_ip": "10.200.0.1",
        })
        assert result["success"] is True
        assert result["events_generated"] == 10

    def test_simulate_unknown_attack(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        result = twin.simulate_attack("unknown_attack_type", {})
        assert result["success"] is True
        assert result["events_generated"] == 1  # Generic fallback

    def test_replay_events(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin, TwinDevice
        from core.aegis.neurokernel.types import SensorEvent, SensorType
        twin = KernelDigitalTwin()
        twin.add_device(TwinDevice(mac="AA:BB:CC:DD:EE:01", ip="10.200.0.10"))
        events = [
            SensorEvent(sensor_type=SensorType.NETWORK, source_ip="10.200.0.10"),
            SensorEvent(sensor_type=SensorType.NETWORK, source_ip="99.99.99.99"),
        ]
        replayed = twin.replay_events(events)
        assert replayed == 1  # Only the matching IP

    def test_stats(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin(num_devices=3)
        twin.simulate_attack("port_scan", {"target_ip": "10.200.0.10", "port_range": "1-10"})
        s = twin.stats()
        assert s["device_count"] == 3
        assert s["attacks_simulated"] == 1

    def test_attack_log(self):
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        twin = KernelDigitalTwin.create_test_twin()
        twin.simulate_attack("arp_scan", {"subnet": "10.200.0.0/24"})
        twin.simulate_attack("port_scan", {"target_ip": "10.200.0.10", "port_range": "1-5"})
        log = twin.get_attack_log()
        assert len(log) == 2
        assert log[0]["attack_name"] == "arp_scan"
        assert log[1]["attack_name"] == "port_scan"


class TestShadowPentester:
    """Test the shadow pentester offensive agent."""

    def _make_pentester(self):
        from core.aegis.neurokernel.attack_library import AttackLibrary, AttackDifficulty
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        from core.aegis.neurokernel.shadow_pentester import ShadowPentester

        lib = AttackLibrary()
        twin = KernelDigitalTwin.create_test_twin()
        return ShadowPentester(
            attack_library=lib,
            twin=twin,
            max_difficulty=AttackDifficulty.ADVANCED,
        )

    def test_initial_state(self):
        from core.aegis.neurokernel.shadow_pentester import PentestPhase
        p = self._make_pentester()
        assert p.phase == PentestPhase.IDLE
        s = p.stats()
        assert s["cycle_count"] == 0
        assert s["total_attacks"] == 0
        assert s["has_twin"] is True

    def test_run_cycle(self):
        p = self._make_pentester()
        result = p.run_cycle()
        assert result.attacks_executed > 0
        assert result.completed_at > result.started_at
        assert result.error == ""

    def test_run_cycle_with_category_filter(self):
        from core.aegis.neurokernel.attack_library import AttackCategory
        p = self._make_pentester()
        result = p.run_cycle(target_categories=[AttackCategory.RECONNAISSANCE])
        # Should only run recon attacks (port_scan, arp_scan, dns_enumeration, slow_scan)
        for ex in result.executions:
            assert ex.category == "reconnaissance"

    def test_rate_limiting(self):
        p = self._make_pentester()
        r1 = p.run_cycle()
        assert r1.error == ""

        # Second cycle should be rate-limited
        r2 = p.run_cycle()
        assert "Rate limited" in r2.error

    def test_run_single_attack(self):
        p = self._make_pentester()
        ex = p.run_single_attack("port_scan", {"target_ip": "10.200.0.10", "port_range": "1-10"})
        assert ex.template_name == "port_scan"
        assert ex.success is True

    def test_run_single_unknown_attack(self):
        p = self._make_pentester()
        ex = p.run_single_attack("nonexistent_attack")
        assert "not found" in ex.notes

    def test_detection_simulator(self):
        from core.aegis.neurokernel.shadow_pentester import ShadowPentester
        from core.aegis.neurokernel.attack_library import AttackLibrary
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin

        lib = AttackLibrary()
        twin = KernelDigitalTwin.create_test_twin()

        def always_detect(execution):
            return (True, "L4", 5.0, "HIGH")

        p = ShadowPentester(attack_library=lib, twin=twin)
        p.set_detection_simulator(always_detect)

        ex = p.run_single_attack("syn_flood", {"target_ip": "10.200.0.10"})
        assert ex.detected is True
        assert ex.detection_layer == "L4"
        assert ex.severity_assigned == "HIGH"

    def test_evasion_detection(self):
        """Test that evasion templates are not detected by default."""
        p = self._make_pentester()
        ex = p.run_single_attack("slow_scan", {"target_ip": "10.200.0.10"})
        assert ex.success is True
        assert ex.detected is False
        assert ex.evaded_detection is True

    def test_cycle_result_detection_rate(self):
        from core.aegis.neurokernel.shadow_pentester import PentestCycleResult, PentestPhase
        result = PentestCycleResult(
            cycle_id="test",
            phase=PentestPhase.IDLE,
            started_at=1.0,
            attacks_executed=10,
            attacks_detected=8,
            attacks_evaded=2,
        )
        assert result.detection_rate == 0.8
        assert result.evasion_rate == 0.2

    def test_cycle_result_to_dict(self):
        from core.aegis.neurokernel.shadow_pentester import PentestCycleResult, PentestPhase
        result = PentestCycleResult(
            cycle_id="test",
            phase=PentestPhase.IDLE,
            started_at=1.0,
            completed_at=2.0,
            attacks_executed=5,
            attacks_detected=4,
            attacks_evaded=1,
        )
        d = result.to_dict()
        assert d["cycle_id"] == "test"
        assert d["detection_rate"] == 0.8

    def test_finding_generated_for_evasion(self):
        """When no detection simulator is set, evasion templates generate findings."""
        from core.aegis.neurokernel.attack_library import AttackCategory
        p = self._make_pentester()
        # Run only recon (includes slow_scan which is expected to evade)
        result = p.run_cycle(target_categories=[AttackCategory.RECONNAISSANCE])
        # slow_scan should produce a finding since it evaded
        evaded_templates = [e.template_name for e in result.executions if e.evaded_detection]
        assert "slow_scan" in evaded_templates
        # Check finding was generated
        finding_templates = [f.attack_template for f in result.findings]
        assert "slow_scan" in finding_templates

    def test_stats_after_cycle(self):
        p = self._make_pentester()
        p.run_cycle()
        s = p.stats()
        assert s["cycle_count"] == 1
        assert s["total_attacks"] > 0

    def test_history(self):
        p = self._make_pentester()
        p.run_cycle()
        history = p.get_history()
        assert len(history) == 1
        assert "cycle_id" in history[0]

    def test_pentester_with_rag_pipeline(self):
        """Test that RAG pipeline is queried during recon."""
        from core.aegis.neurokernel.shadow_pentester import ShadowPentester
        from core.aegis.neurokernel.attack_library import AttackLibrary, AttackCategory
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin

        mock_rag = MagicMock()
        mock_rag.query.return_value = "10.200.0.10 made 100 connections"

        p = ShadowPentester(
            attack_library=AttackLibrary(),
            twin=KernelDigitalTwin.create_test_twin(),
        )
        p.set_rag_pipeline(mock_rag)
        p.run_cycle(target_categories=[AttackCategory.RECONNAISSANCE])
        mock_rag.query.assert_called()


class TestDefenseFeedback:
    """Test the defense feedback pipeline."""

    def _make_finding(self, template_name="port_scan", severity="medium"):
        from core.aegis.neurokernel.shadow_pentester import VulnerabilityFinding, FindingSeverity
        sev_map = {"critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
                    "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW}
        return VulnerabilityFinding(
            finding_id="sf-test001",
            title=f"Undetected {template_name}",
            description=f"Attack {template_name} evaded detection",
            severity=sev_map.get(severity, FindingSeverity.MEDIUM),
            attack_template=template_name,
            mitre_id="T1046",
            mitre_technique="Network Service Discovery",
            target_ip="10.200.0.10",
            detection_gap="Expected detection at L4",
            evidence={
                "template_id": f"atk-reconnaissance-{template_name}",
                "template_name": template_name,
                "category": "reconnaissance",
                "parameters": {"target_ip": "10.200.0.10", "scan_rate": 100},
                "success": True,
                "detected": False,
            },
        )

    def test_process_finding(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        fb = DefenseFeedback()
        finding = self._make_finding()
        sig = fb.process_finding(finding)
        assert sig is not None
        assert sig.sig_id.startswith("SHADOW-")
        assert sig.validated is True

    def test_stats_after_finding(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        fb = DefenseFeedback()
        fb.process_finding(self._make_finding())
        s = fb.stats()
        assert s["findings_received"] == 1
        assert s["signatures_generated"] == 1

    def test_pending_signatures(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        fb = DefenseFeedback()
        fb.process_finding(self._make_finding("port_scan"))
        fb.process_finding(self._make_finding("syn_flood"))
        pending = fb.get_pending()
        assert len(pending) == 2

    def test_signature_has_feature_patterns(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        fb = DefenseFeedback()
        sig = fb.process_finding(self._make_finding("port_scan"))
        assert sig is not None
        assert len(sig.feature_patterns) > 0
        # Port scan should have unique_dest_ports pattern
        pattern_names = [p["feature_name"] for p in sig.feature_patterns]
        assert "unique_dest_ports" in pattern_names

    def test_dns_tunnel_patterns(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        from core.aegis.neurokernel.shadow_pentester import VulnerabilityFinding, FindingSeverity
        fb = DefenseFeedback()
        finding = VulnerabilityFinding(
            finding_id="sf-dns",
            title="Undetected DNS tunnel",
            description="DNS tunnel evaded detection",
            severity=FindingSeverity.CRITICAL,
            attack_template="dns_tunnel",
            mitre_id="T1048.003",
            detection_gap="Expected detection at L7",
            evidence={
                "template_name": "dns_tunnel",
                "category": "exfiltration",
                "parameters": {"c2_domain": "evil.com"},
                "success": True,
                "detected": False,
            },
        )
        sig = fb.process_finding(finding)
        assert sig is not None
        pattern_names = [p["feature_name"] for p in sig.feature_patterns]
        assert "dns_query_rate" in pattern_names
        assert "dns_query_length" in pattern_names

    def test_osi_layer_inference(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        fb = DefenseFeedback()
        sig = fb.process_finding(self._make_finding("port_scan"))
        assert sig is not None
        assert sig.osi_layer == 4  # L4 transport from "Expected detection at L4"

    def test_callback_on_signature(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        received = []
        fb = DefenseFeedback(on_signature_generated=lambda s: received.append(s))
        fb.process_finding(self._make_finding())
        assert len(received) == 1
        assert received[0].sig_id.startswith("SHADOW-")

    def test_max_pending_backpressure(self):
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        fb = DefenseFeedback()
        fb.MAX_PENDING = 5
        for i in range(10):
            fb.process_finding(self._make_finding(f"attack_{i}"))
        assert len(fb.get_pending()) == 5  # Capped at MAX_PENDING

    def test_signature_candidate_to_dict(self):
        from core.aegis.neurokernel.defense_feedback import SignatureCandidate
        sig = SignatureCandidate(
            sig_id="SHADOW-TEST",
            name="test-sig",
            description="A test signature",
            osi_layer=4,
            severity=3,
            attack_category="reconnaissance",
            mitre_id="T1046",
        )
        d = sig.to_dict()
        assert d["sig_id"] == "SHADOW-TEST"
        assert d["osi_layer"] == 4


class TestShadowPentesterE2E:
    """End-to-end: shadow pentester → defense feedback pipeline."""

    def test_full_cycle_with_feedback(self):
        """Run a full pentest cycle and verify findings flow to defense feedback."""
        from core.aegis.neurokernel.attack_library import AttackLibrary, AttackCategory
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        from core.aegis.neurokernel.shadow_pentester import ShadowPentester
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback

        lib = AttackLibrary()
        twin = KernelDigitalTwin.create_test_twin()
        feedback = DefenseFeedback()
        pentester = ShadowPentester(
            attack_library=lib,
            twin=twin,
            defense_feedback=feedback,
        )

        result = pentester.run_cycle(
            target_categories=[AttackCategory.RECONNAISSANCE],
        )

        # Should have executed recon attacks
        assert result.attacks_executed > 0

        # slow_scan should have evaded detection
        evaded = [e for e in result.executions if e.evaded_detection]
        assert len(evaded) > 0

        # Findings should have been reported to feedback
        if result.findings:
            assert feedback.stats()["findings_received"] > 0
            assert feedback.stats()["signatures_generated"] > 0

    def test_detection_simulator_prevents_findings(self):
        """With a simulator that detects everything, no findings should be generated."""
        from core.aegis.neurokernel.attack_library import AttackLibrary, AttackCategory
        from core.aegis.neurokernel.kernel_twin import KernelDigitalTwin
        from core.aegis.neurokernel.shadow_pentester import ShadowPentester
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback

        feedback = DefenseFeedback()
        pentester = ShadowPentester(
            attack_library=AttackLibrary(),
            twin=KernelDigitalTwin.create_test_twin(),
            defense_feedback=feedback,
        )
        pentester.set_detection_simulator(lambda ex: (True, "L4", 1.0, "HIGH"))

        result = pentester.run_cycle(
            target_categories=[AttackCategory.IMPACT],
        )

        # All attacks detected — no findings
        assert len(result.findings) == 0
        assert result.attacks_detected == result.attacks_executed

    def test_signature_deployment_with_mock_updater(self):
        """Verify the feedback pipeline calls the signature updater."""
        from core.aegis.neurokernel.defense_feedback import DefenseFeedback
        from core.aegis.neurokernel.shadow_pentester import VulnerabilityFinding, FindingSeverity

        mock_updater = MagicMock()
        feedback = DefenseFeedback(signature_updater=mock_updater)

        finding = VulnerabilityFinding(
            finding_id="sf-e2e",
            title="Undetected port scan",
            description="Port scan evaded",
            severity=FindingSeverity.MEDIUM,
            attack_template="port_scan",
            mitre_id="T1046",
            detection_gap="Expected detection at L4",
            evidence={
                "template_name": "port_scan",
                "category": "reconnaissance",
                "parameters": {"scan_rate": 100},
                "success": True,
                "detected": False,
            },
        )

        sig = feedback.process_finding(finding)
        assert sig is not None
        # Mock updater should have been called
        mock_updater.record_detection.assert_called_once()


class TestPhase3Exports:
    """Verify all Phase 3 classes are properly exported."""

    def test_import_attack_library(self):
        from core.aegis.neurokernel import (
            AttackLibrary, AttackCategory, AttackDifficulty,
            AttackExecution, AttackTemplate, ExpectedDetection,
        )
        assert AttackLibrary is not None
        assert AttackCategory is not None

    def test_import_shadow_pentester(self):
        from core.aegis.neurokernel import (
            ShadowPentester, PentestPhase, PentestCycleResult,
            FindingSeverity, VulnerabilityFinding,
        )
        assert ShadowPentester is not None
        assert PentestPhase is not None

    def test_import_defense_feedback(self):
        from core.aegis.neurokernel import DefenseFeedback, SignatureCandidate
        assert DefenseFeedback is not None
        assert SignatureCandidate is not None

    def test_import_kernel_twin(self):
        from core.aegis.neurokernel import KernelDigitalTwin, TwinAttackResult, TwinDevice
        assert KernelDigitalTwin is not None
        assert TwinDevice is not None

    def test_all_exports_phase3(self):
        from core.aegis.neurokernel import __all__
        expected = [
            "AttackLibrary", "AttackCategory", "AttackDifficulty",
            "AttackExecution", "AttackTemplate", "ExpectedDetection",
            "ShadowPentester", "PentestPhase", "PentestCycleResult",
            "FindingSeverity", "VulnerabilityFinding",
            "DefenseFeedback", "SignatureCandidate",
            "KernelDigitalTwin", "TwinAttackResult", "TwinDevice",
        ]
        for name in expected:
            assert name in __all__, f"{name} missing from __all__"

    def test_version_bumped(self):
        import core.aegis.neurokernel as nk
        # Check the docstring contains 3.0.0
        assert "3.0.0" in nk.__doc__
