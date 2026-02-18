const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================================================================
    // XDP/eBPF Program (compiled for BPF target)
    // =========================================================================
    const bpf_target = std.Target.Query{
        .cpu_arch = .bpfel,
        .os_tag = .freestanding,
        .abi = .none,
    };

    const xdp_obj = b.addObject(.{
        .name = "aegis_xdp",
        .root_source_file = b.path("src/xdp_program.zig"),
        .target = b.resolveTargetQuery(bpf_target),
        .optimize = .ReleaseFast, // Always optimize BPF programs
    });

    // Install the BPF object file
    const install_xdp = b.addInstallBinFile(xdp_obj.getEmittedBin(), "aegis_xdp.o");
    b.getInstallStep().dependOn(&install_xdp.step);

    // =========================================================================
    // Userspace Loader + Ring Buffer Manager
    // =========================================================================
    const loader = b.addExecutable(.{
        .name = "aegis-loader",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    loader.linkLibC(); // Required for libbpf FFI
    loader.linkSystemLibrary("bpf"); // libbpf
    loader.linkSystemLibrary("elf"); // libelf (libbpf dependency)
    loader.linkSystemLibrary("z"); // zlib (libbpf dependency)

    b.installArtifact(loader);

    // =========================================================================
    // Tests
    // =========================================================================
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run Aegis unit tests");
    test_step.dependOn(&run_tests.step);

    // =========================================================================
    // Run step
    // =========================================================================
    const run_cmd = b.addRunArtifact(loader);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run Aegis loader");
    run_step.dependOn(&run_cmd.step);
}
