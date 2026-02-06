use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // BPF compilation is Linux-only.
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "linux" {
        println!("cargo:warning=BPF compilation skipped on non-Linux target");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));

    let bpf_src = manifest_dir.join("bpf/observoor.c");
    let bpf_out = out_dir.join("observoor.bpf.o");

    // Determine target architecture for BPF.
    let target_arch = match env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        arch => {
            println!("cargo:warning=Unsupported BPF target arch: {arch}, defaulting to x86");
            "x86"
        }
    };

    let bpf_cflags = format!("-D__TARGET_ARCH_{target_arch}");

    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-target",
            "bpf",
            &bpf_cflags,
            "-I",
            manifest_dir
                .join("bpf/headers")
                .to_str()
                .expect("valid path"),
            "-I",
            manifest_dir
                .join("bpf/include")
                .to_str()
                .expect("valid path"),
            "-c",
            bpf_src.to_str().expect("valid path"),
            "-o",
            bpf_out.to_str().expect("valid path"),
        ])
        .status()
        .expect("failed to execute clang - is it installed?");

    if !status.success() {
        eprintln!("BPF compilation failed with status: {status}");
        std::process::exit(1);
    }

    // Strip DWARF debug sections from the BPF object, keeping BTF.
    //
    // Clang-14+ defaults to DWARFv5 which aya-obj's ELF parser cannot handle.
    // BTF sections (.BTF, .BTF.ext) are preserved for CO-RE relocations.
    // This matches what Go's bpf2go does (cilium/ebpf#429).
    let strip_status = Command::new("llvm-strip")
        .args(["-g", bpf_out.to_str().expect("valid path")])
        .status()
        .expect("failed to execute llvm-strip - is llvm installed?");

    if !strip_status.success() {
        eprintln!("BPF DWARF strip failed with status: {strip_status}");
        std::process::exit(1);
    }

    // Log BPF object size for diagnostics.
    match std::fs::metadata(&bpf_out) {
        Ok(meta) => println!(
            "cargo:warning=BPF object size after strip: {} bytes",
            meta.len()
        ),
        Err(e) => {
            eprintln!("Failed to stat BPF object: {e}");
            std::process::exit(1);
        }
    }

    // Tell cargo to rerun if BPF sources change.
    println!("cargo:rerun-if-changed=bpf/");
    println!("cargo:rerun-if-changed=build.rs");
}
