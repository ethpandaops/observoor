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

    // Tell cargo to rerun if BPF sources change.
    println!("cargo:rerun-if-changed=bpf/");
    println!("cargo:rerun-if-changed=build.rs");
}
