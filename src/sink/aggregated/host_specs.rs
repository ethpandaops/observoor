use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Snapshot of host-level machine specifications.
#[derive(Debug, Clone)]
pub struct HostSpecsSnapshot {
    pub host_id: String,
    pub kernel_release: String,
    pub os_name: String,
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_vendor: String,
    pub cpu_online_cores: u16,
    pub cpu_logical_cores: u16,
    pub cpu_physical_cores: u16,
    pub cpu_performance_cores: u16,
    pub cpu_efficiency_cores: u16,
    pub cpu_unknown_type_cores: u16,
    pub cpu_logical_ids: Vec<u16>,
    pub cpu_core_ids: Vec<i32>,
    pub cpu_package_ids: Vec<i32>,
    pub cpu_die_ids: Vec<i32>,
    pub cpu_cluster_ids: Vec<i32>,
    pub cpu_core_types: Vec<u8>,
    pub cpu_core_type_labels: Vec<String>,
    pub cpu_online_flags: Vec<u8>,
    pub cpu_max_freq_khz: Vec<u64>,
    pub cpu_base_freq_khz: Vec<u64>,
    pub memory_total_bytes: u64,
    pub memory_type: String,
    pub memory_speed_mts: u32,
    pub memory_dimm_count: u16,
    pub memory_dimm_sizes_bytes: Vec<u64>,
    pub memory_dimm_types: Vec<String>,
    pub memory_dimm_speeds_mts: Vec<u32>,
    pub memory_dimm_configured_speeds_mts: Vec<u32>,
    pub memory_dimm_locators: Vec<String>,
    pub memory_dimm_bank_locators: Vec<String>,
    pub memory_dimm_manufacturers: Vec<String>,
    pub memory_dimm_part_numbers: Vec<String>,
    pub memory_dimm_serials: Vec<String>,
    pub disk_count: u16,
    pub disk_total_bytes: u64,
    pub disk_names: Vec<String>,
    pub disk_models: Vec<String>,
    pub disk_vendors: Vec<String>,
    pub disk_serials: Vec<String>,
    pub disk_sizes_bytes: Vec<u64>,
    pub disk_rotational: Vec<u8>,
}

/// Collects host-level machine specifications from procfs/sysfs/DMI.
pub fn collect_host_specs() -> HostSpecsSnapshot {
    let hostname = read_text_file("/proc/sys/kernel/hostname").unwrap_or_default();
    let machine_id = read_text_file("/etc/machine-id").unwrap_or_default();
    let kernel_release = read_text_file("/proc/sys/kernel/osrelease").unwrap_or_default();
    let os_name = read_os_name().unwrap_or_default();
    let architecture = std::env::consts::ARCH.to_string();

    let host_id = build_host_id(&machine_id, &hostname, &kernel_release, &architecture);

    let cpuinfo = read_text_file("/proc/cpuinfo").unwrap_or_default();
    let (cpu_model, cpu_vendor, cpu_logical_cores_from_cpuinfo) = parse_cpuinfo(&cpuinfo);
    let cpu_topology = read_cpu_topology();

    let cpu_logical_cores = if cpu_topology.logical_cores > 0 {
        cpu_topology.logical_cores
    } else {
        cpu_logical_cores_from_cpuinfo
    };

    let cpu_online_cores = if cpu_topology.online_cores > 0 {
        cpu_topology.online_cores
    } else {
        read_cpu_online().unwrap_or(cpu_logical_cores)
    };

    let cpu_physical_cores = if cpu_topology.physical_cores > 0 {
        cpu_topology.physical_cores
    } else {
        cpu_online_cores
    };

    let meminfo = read_text_file("/proc/meminfo").unwrap_or_default();
    let memory_total_bytes = parse_mem_total_bytes(&meminfo).unwrap_or(0);

    let memory_dmi = read_memory_dmi();
    let disks = read_disk_specs();

    HostSpecsSnapshot {
        host_id,
        kernel_release,
        os_name,
        architecture,
        cpu_model,
        cpu_vendor,
        cpu_online_cores,
        cpu_logical_cores,
        cpu_physical_cores,
        cpu_performance_cores: cpu_topology.performance_cores,
        cpu_efficiency_cores: cpu_topology.efficiency_cores,
        cpu_unknown_type_cores: cpu_topology.unknown_type_cores,
        cpu_logical_ids: cpu_topology.logical_ids,
        cpu_core_ids: cpu_topology.core_ids,
        cpu_package_ids: cpu_topology.package_ids,
        cpu_die_ids: cpu_topology.die_ids,
        cpu_cluster_ids: cpu_topology.cluster_ids,
        cpu_core_types: cpu_topology.core_types,
        cpu_core_type_labels: cpu_topology.core_type_labels,
        cpu_online_flags: cpu_topology.online_flags,
        cpu_max_freq_khz: cpu_topology.max_freq_khz,
        cpu_base_freq_khz: cpu_topology.base_freq_khz,
        memory_total_bytes,
        memory_type: memory_dmi.memory_type,
        memory_speed_mts: memory_dmi.memory_speed_mts,
        memory_dimm_count: memory_dmi.dimm_count,
        memory_dimm_sizes_bytes: memory_dmi.dimm_sizes_bytes,
        memory_dimm_types: memory_dmi.dimm_types,
        memory_dimm_speeds_mts: memory_dmi.dimm_speeds_mts,
        memory_dimm_configured_speeds_mts: memory_dmi.dimm_configured_speeds_mts,
        memory_dimm_locators: memory_dmi.dimm_locators,
        memory_dimm_bank_locators: memory_dmi.dimm_bank_locators,
        memory_dimm_manufacturers: memory_dmi.dimm_manufacturers,
        memory_dimm_part_numbers: memory_dmi.dimm_part_numbers,
        memory_dimm_serials: memory_dmi.dimm_serials,
        disk_count: disks.count,
        disk_total_bytes: disks.total_bytes,
        disk_names: disks.names,
        disk_models: disks.models,
        disk_vendors: disks.vendors,
        disk_serials: disks.serials,
        disk_sizes_bytes: disks.sizes_bytes,
        disk_rotational: disks.rotational,
    }
}

fn read_text_file(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    Some(text.trim().to_string())
}

fn read_u8_file(path: &Path) -> Option<u8> {
    let text = fs::read_to_string(path).ok()?;
    text.trim().parse::<u8>().ok()
}

fn read_u64_file(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    text.trim().parse::<u64>().ok()
}

fn read_i32_file(path: &Path) -> Option<i32> {
    let text = fs::read_to_string(path).ok()?;
    text.trim().parse::<i32>().ok()
}

fn read_os_name() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    parse_os_release_pretty_name(&content)
}

fn parse_os_release_pretty_name(content: &str) -> Option<String> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return Some(strip_quotes(v).to_string());
        }
        if let Some(v) = line.strip_prefix("NAME=") {
            name = Some(strip_quotes(v).to_string());
            continue;
        }
        if let Some(v) = line.strip_prefix("VERSION=") {
            version = Some(strip_quotes(v).to_string());
        }
    }

    match (name, version) {
        (Some(n), Some(v)) if !v.is_empty() => Some(format!("{n} {v}")),
        (Some(n), _) => Some(n),
        _ => None,
    }
}

fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(s)
}

fn build_host_id(
    machine_id: &str,
    hostname: &str,
    kernel_release: &str,
    architecture: &str,
) -> String {
    let source = if !machine_id.is_empty() {
        format!("machine-id:{machine_id}")
    } else if !hostname.is_empty() {
        format!("hostname:{hostname}")
    } else {
        format!("fallback:{kernel_release}:{architecture}")
    };

    let mut hasher = Sha256::new();
    hasher.update(b"observoor-host-id-v1:");
    hasher.update(source.as_bytes());
    let digest = hasher.finalize();

    let mut id = String::with_capacity(34);
    id.push_str("h_");
    for byte in digest.iter().take(16) {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

fn parse_cpuinfo(cpuinfo: &str) -> (String, String, u16) {
    let mut model = String::new();
    let mut vendor = String::new();
    let mut logical = 0u32;

    for line in cpuinfo.lines() {
        if model.is_empty() {
            if let Some(v) = line.strip_prefix("model name\t:") {
                model = v.trim().to_string();
                continue;
            }
        }
        if vendor.is_empty() {
            if let Some(v) = line.strip_prefix("vendor_id\t:") {
                vendor = v.trim().to_string();
                continue;
            }
        }
        if line.starts_with("processor\t:") {
            logical = logical.saturating_add(1);
        }
    }

    if model.is_empty() {
        if let Some(v) = cpuinfo
            .lines()
            .find_map(|line| line.strip_prefix("Hardware\t:"))
        {
            model = v.trim().to_string();
        }
    }
    if vendor.is_empty() {
        vendor = "unknown".to_string();
    }

    let logical = if logical == 0 {
        1
    } else {
        logical.min(u32::from(u16::MAX))
    };

    (model, vendor, logical as u16)
}

fn parse_mem_total_bytes(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

fn read_cpu_online() -> Option<u16> {
    let text = fs::read_to_string("/sys/devices/system/cpu/online").ok()?;
    let online = parse_cpu_online_text(text.trim())?;
    Some(online.min(u32::from(u16::MAX)) as u16)
}

fn parse_cpu_online_text(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }

    let mut total = 0u32;
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start, end)) = part.split_once('-') {
            let start = start.trim().parse::<u32>().ok()?;
            let end = end.trim().parse::<u32>().ok()?;
            if end < start {
                return None;
            }
            total = total.saturating_add(end.saturating_sub(start).saturating_add(1));
        } else {
            let _ = part.parse::<u32>().ok()?;
            total = total.saturating_add(1);
        }
    }

    if total == 0 {
        None
    } else {
        Some(total)
    }
}

#[derive(Debug, Default)]
struct CpuTopologySnapshot {
    logical_cores: u16,
    online_cores: u16,
    physical_cores: u16,
    performance_cores: u16,
    efficiency_cores: u16,
    unknown_type_cores: u16,
    logical_ids: Vec<u16>,
    core_ids: Vec<i32>,
    package_ids: Vec<i32>,
    die_ids: Vec<i32>,
    cluster_ids: Vec<i32>,
    core_types: Vec<u8>,
    core_type_labels: Vec<String>,
    online_flags: Vec<u8>,
    max_freq_khz: Vec<u64>,
    base_freq_khz: Vec<u64>,
}

#[derive(Debug)]
struct CpuLogicalSnapshot {
    logical_id: u16,
    core_id: i32,
    package_id: i32,
    die_id: i32,
    cluster_id: i32,
    core_type: u8,
    online: u8,
    max_freq_khz: u64,
    base_freq_khz: u64,
}

fn read_cpu_topology() -> CpuTopologySnapshot {
    let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") else {
        return CpuTopologySnapshot::default();
    };

    let mut cpus = Vec::<CpuLogicalSnapshot>::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        let Some(id_text) = name.strip_prefix("cpu") else {
            continue;
        };
        if id_text.is_empty() || !id_text.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }

        let Ok(logical_id_u32) = id_text.parse::<u32>() else {
            continue;
        };
        if logical_id_u32 > u32::from(u16::MAX) {
            continue;
        }

        let base = entry.path();
        let online = read_u8_file(&base.join("online")).unwrap_or(1).min(1);

        cpus.push(CpuLogicalSnapshot {
            logical_id: logical_id_u32 as u16,
            core_id: read_i32_file(&base.join("topology/core_id")).unwrap_or(-1),
            package_id: read_i32_file(&base.join("topology/physical_package_id")).unwrap_or(-1),
            die_id: read_i32_file(&base.join("topology/die_id")).unwrap_or(-1),
            cluster_id: read_i32_file(&base.join("topology/cluster_id")).unwrap_or(-1),
            core_type: read_u8_file(&base.join("topology/core_type")).unwrap_or(0),
            online,
            max_freq_khz: read_u64_file(&base.join("cpufreq/cpuinfo_max_freq")).unwrap_or(0),
            base_freq_khz: read_u64_file(&base.join("cpufreq/base_frequency")).unwrap_or(0),
        });
    }

    cpus.sort_by_key(|cpu| cpu.logical_id);

    let mut snapshot = CpuTopologySnapshot {
        logical_cores: cpus.len().min(usize::from(u16::MAX)) as u16,
        ..Default::default()
    };

    let mut unique_physical = HashSet::<(i32, i32)>::new();

    for cpu in cpus {
        if cpu.online == 1 {
            snapshot.online_cores = snapshot.online_cores.saturating_add(1);
        }

        match cpu.core_type {
            2 => snapshot.performance_cores = snapshot.performance_cores.saturating_add(1),
            1 => snapshot.efficiency_cores = snapshot.efficiency_cores.saturating_add(1),
            _ => snapshot.unknown_type_cores = snapshot.unknown_type_cores.saturating_add(1),
        }

        if cpu.core_id >= 0 {
            let package = if cpu.package_id >= 0 {
                cpu.package_id
            } else {
                0
            };
            unique_physical.insert((package, cpu.core_id));
        }

        snapshot.logical_ids.push(cpu.logical_id);
        snapshot.core_ids.push(cpu.core_id);
        snapshot.package_ids.push(cpu.package_id);
        snapshot.die_ids.push(cpu.die_id);
        snapshot.cluster_ids.push(cpu.cluster_id);
        snapshot.core_types.push(cpu.core_type);
        snapshot
            .core_type_labels
            .push(cpu_core_type_label(cpu.core_type).to_string());
        snapshot.online_flags.push(cpu.online);
        snapshot.max_freq_khz.push(cpu.max_freq_khz);
        snapshot.base_freq_khz.push(cpu.base_freq_khz);
    }

    if !unique_physical.is_empty() {
        snapshot.physical_cores = unique_physical.len().min(usize::from(u16::MAX)) as u16;
    }

    snapshot
}

fn cpu_core_type_label(core_type: u8) -> &'static str {
    // Linux exposes hybrid x86 core types as: 1=Atom(E-core), 2=Core(P-core).
    match core_type {
        1 => "efficiency",
        2 => "performance",
        _ => "unknown",
    }
}

#[derive(Debug, Default)]
struct MemoryDmiSnapshot {
    memory_type: String,
    memory_speed_mts: u32,
    dimm_count: u16,
    dimm_sizes_bytes: Vec<u64>,
    dimm_types: Vec<String>,
    dimm_speeds_mts: Vec<u32>,
    dimm_configured_speeds_mts: Vec<u32>,
    dimm_locators: Vec<String>,
    dimm_bank_locators: Vec<String>,
    dimm_manufacturers: Vec<String>,
    dimm_part_numbers: Vec<String>,
    dimm_serials: Vec<String>,
}

#[derive(Debug, Default)]
struct MemoryDimmRecord {
    installed: bool,
    size_bytes: u64,
    memory_type: String,
    speed_mts: u32,
    configured_speed_mts: u32,
    locator: String,
    bank_locator: String,
    manufacturer: String,
    part_number: String,
    serial_number: String,
}

fn read_memory_dmi() -> MemoryDmiSnapshot {
    let output = Command::new("dmidecode").args(["-t", "memory"]).output();
    let Ok(output) = output else {
        return MemoryDmiSnapshot::default();
    };
    if !output.status.success() {
        return MemoryDmiSnapshot::default();
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_dmidecode_memory(&text)
}

fn parse_dmidecode_memory(text: &str) -> MemoryDmiSnapshot {
    let mut snapshot = MemoryDmiSnapshot::default();
    let mut current: Option<MemoryDimmRecord> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed == "Memory Device" {
            if let Some(record) = current.take() {
                append_dimm_record(&mut snapshot, record);
            }
            current = Some(MemoryDimmRecord::default());
            continue;
        }

        let Some(record) = current.as_mut() else {
            continue;
        };

        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        match key {
            "Size" => {
                if let Some(size_bytes) = parse_dmi_size_bytes(value) {
                    record.installed = true;
                    record.size_bytes = size_bytes;
                }
            }
            "Type" => record.memory_type = sanitize_dmi_text(value),
            "Speed" => record.speed_mts = parse_speed_mts(value),
            "Configured Memory Speed" => {
                record.configured_speed_mts = parse_speed_mts(value);
            }
            "Locator" => record.locator = sanitize_dmi_text(value),
            "Bank Locator" => record.bank_locator = sanitize_dmi_text(value),
            "Manufacturer" => record.manufacturer = sanitize_dmi_text(value),
            "Part Number" => record.part_number = sanitize_dmi_text(value),
            "Serial Number" => record.serial_number = sanitize_dmi_text(value),
            _ => {}
        }
    }

    if let Some(record) = current.take() {
        append_dimm_record(&mut snapshot, record);
    }

    snapshot
}

fn append_dimm_record(snapshot: &mut MemoryDmiSnapshot, record: MemoryDimmRecord) {
    if !record.installed || record.size_bytes == 0 {
        return;
    }

    snapshot.dimm_count = snapshot.dimm_count.saturating_add(1);

    if snapshot.memory_type.is_empty() && !record.memory_type.is_empty() {
        snapshot.memory_type = record.memory_type.clone();
    }

    let effective_speed_mts = if record.configured_speed_mts > 0 {
        record.configured_speed_mts
    } else {
        record.speed_mts
    };
    snapshot.memory_speed_mts = snapshot.memory_speed_mts.max(effective_speed_mts);

    snapshot.dimm_sizes_bytes.push(record.size_bytes);
    snapshot.dimm_types.push(record.memory_type);
    snapshot.dimm_speeds_mts.push(record.speed_mts);
    snapshot
        .dimm_configured_speeds_mts
        .push(record.configured_speed_mts);
    snapshot.dimm_locators.push(record.locator);
    snapshot.dimm_bank_locators.push(record.bank_locator);
    snapshot.dimm_manufacturers.push(record.manufacturer);
    snapshot.dimm_part_numbers.push(record.part_number);
    snapshot.dimm_serials.push(record.serial_number);
}

fn sanitize_dmi_text(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }

    let lowered = value.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "unknown"
            | "none"
            | "not specified"
            | "not provided"
            | "n/a"
            | "to be filled by o.e.m."
            | "no module installed"
    ) {
        return String::new();
    }

    value.to_string()
}

fn parse_dmi_size_bytes(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let lowered = raw.to_ascii_lowercase();
    if lowered.contains("no module installed") || lowered == "unknown" {
        return None;
    }

    let mut parts = raw.split_whitespace();
    let number = parts.next()?.replace(',', "");
    let value = number.parse::<u64>().ok()?;
    let unit = parts.next().unwrap_or("B").to_ascii_lowercase();

    let multiplier = if unit.starts_with("tb") {
        1024u64.pow(4)
    } else if unit.starts_with("gb") {
        1024u64.pow(3)
    } else if unit.starts_with("mb") {
        1024u64.pow(2)
    } else if unit.starts_with("kb") {
        1024u64
    } else {
        1u64
    };

    Some(value.saturating_mul(multiplier))
}

fn parse_speed_mts(raw: &str) -> u32 {
    raw.split_whitespace()
        .find_map(|part| part.parse::<u32>().ok())
        .unwrap_or(0)
}

#[derive(Debug, Default)]
struct DiskSpecsSnapshot {
    count: u16,
    total_bytes: u64,
    names: Vec<String>,
    models: Vec<String>,
    vendors: Vec<String>,
    serials: Vec<String>,
    sizes_bytes: Vec<u64>,
    rotational: Vec<u8>,
}

#[derive(Debug)]
struct DiskDeviceSnapshot {
    name: String,
    model: String,
    vendor: String,
    serial: String,
    size_bytes: u64,
    rotational: u8,
}

fn read_disk_specs() -> DiskSpecsSnapshot {
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return DiskSpecsSnapshot::default();
    };

    let mut devices = Vec::<DiskDeviceSnapshot>::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if should_skip_block_device(&name) {
            continue;
        }

        let base = entry.path();
        devices.push(DiskDeviceSnapshot {
            name: name.to_string(),
            model: read_block_model(&base).unwrap_or_else(|| "unknown".to_string()),
            vendor: read_block_vendor(&base).unwrap_or_default(),
            serial: read_block_serial(&base).unwrap_or_default(),
            size_bytes: read_block_size_bytes(&base).unwrap_or(0),
            rotational: read_block_rotational(&base).unwrap_or(0),
        });
    }

    devices.sort_by(|a, b| a.name.cmp(&b.name));

    let mut snapshot = DiskSpecsSnapshot {
        count: devices.len().min(usize::from(u16::MAX)) as u16,
        ..Default::default()
    };

    for disk in devices {
        snapshot.total_bytes = snapshot.total_bytes.saturating_add(disk.size_bytes);
        snapshot.names.push(disk.name);
        snapshot.models.push(disk.model);
        snapshot.vendors.push(disk.vendor);
        snapshot.serials.push(disk.serial);
        snapshot.sizes_bytes.push(disk.size_bytes);
        snapshot.rotational.push(disk.rotational);
    }

    snapshot
}

fn should_skip_block_device(name: &str) -> bool {
    name.starts_with("loop") || name.starts_with("ram")
}

fn read_block_size_bytes(base: &Path) -> Option<u64> {
    let sectors = fs::read_to_string(base.join("size")).ok()?;
    let sectors = sectors.trim().parse::<u64>().ok()?;
    Some(sectors.saturating_mul(512))
}

fn read_block_model(base: &Path) -> Option<String> {
    let model_path = base.join("device/model");
    if let Ok(model) = fs::read_to_string(model_path) {
        let model = model.trim();
        if !model.is_empty() {
            return Some(model.to_string());
        }
    }

    let name_path = base.join("device/name");
    let name = fs::read_to_string(name_path).ok()?;
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn read_block_vendor(base: &Path) -> Option<String> {
    let vendor = fs::read_to_string(base.join("device/vendor")).ok()?;
    let vendor = vendor.trim();
    if vendor.is_empty() {
        None
    } else {
        Some(vendor.to_string())
    }
}

fn read_block_serial(base: &Path) -> Option<String> {
    let serial = fs::read_to_string(base.join("device/serial")).ok()?;
    let serial = serial.trim();
    if serial.is_empty() {
        None
    } else {
        Some(serial.to_string())
    }
}

fn read_block_rotational(base: &Path) -> Option<u8> {
    let rotational = fs::read_to_string(base.join("queue/rotational")).ok()?;
    let rotational = rotational.trim().parse::<u8>().ok()?;
    Some(rotational.min(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release_pretty_name() {
        let content = r#"
NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
PRETTY_NAME="Ubuntu 24.04.1 LTS"
"#;
        assert_eq!(
            parse_os_release_pretty_name(content).as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
    }

    #[test]
    fn test_parse_os_release_name_version_fallback() {
        let content = r#"
NAME="Debian GNU/Linux"
VERSION="12 (bookworm)"
"#;
        assert_eq!(
            parse_os_release_pretty_name(content).as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
    }

    #[test]
    fn test_build_host_id_redacts_source() {
        let host_id = build_host_id("abc123", "node01", "6.8.0", "x86_64");
        assert!(host_id.starts_with("h_"));
        assert_eq!(host_id.len(), 34);
        assert!(!host_id.contains("abc123"));
        assert!(!host_id.contains("node01"));
        assert_eq!(
            host_id,
            build_host_id("abc123", "node01", "6.8.0", "x86_64")
        );
    }

    #[test]
    fn test_parse_cpuinfo() {
        let cpuinfo = r#"
processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU
processor	: 1
"#;
        let (model, vendor, logical) = parse_cpuinfo(cpuinfo);
        assert_eq!(model, "Intel(R) Xeon(R) CPU");
        assert_eq!(vendor, "GenuineIntel");
        assert_eq!(logical, 2);
    }

    #[test]
    fn test_parse_mem_total_bytes() {
        let meminfo = "MemTotal:       16384000 kB\nMemFree:         1000 kB\n";
        assert_eq!(parse_mem_total_bytes(meminfo), Some(16_777_216_000));
    }

    #[test]
    fn test_parse_cpu_online_text() {
        assert_eq!(parse_cpu_online_text("0-3"), Some(4));
        assert_eq!(parse_cpu_online_text("0,2,4-5"), Some(4));
        assert_eq!(parse_cpu_online_text(""), None);
    }

    #[test]
    fn test_parse_dmi_size_bytes() {
        assert_eq!(parse_dmi_size_bytes("16384 MB"), Some(17_179_869_184));
        assert_eq!(parse_dmi_size_bytes("16 GB"), Some(17_179_869_184));
        assert_eq!(parse_dmi_size_bytes("No Module Installed"), None);
    }

    #[test]
    fn test_parse_dmidecode_memory() {
        let sample = r#"
Memory Device
	Size: 32768 MB
	Locator: DIMM_A1
	Bank Locator: BANK 0
	Type: DDR5
	Speed: 5600 MT/s
	Configured Memory Speed: 5200 MT/s
	Manufacturer: Kingston
	Part Number: ABC123
	Serial Number: SN123
Memory Device
	Size: No Module Installed
	Locator: DIMM_A2
Memory Device
	Size: 32768 MB
	Locator: DIMM_B1
	Bank Locator: BANK 1
	Type: DDR5
	Speed: 5600 MT/s
	Configured Memory Speed: 5200 MT/s
	Manufacturer: Kingston
	Part Number: ABC123
	Serial Number: SN124
"#;
        let snap = parse_dmidecode_memory(sample);
        assert_eq!(snap.memory_type, "DDR5");
        assert_eq!(snap.memory_speed_mts, 5200);
        assert_eq!(snap.dimm_count, 2);
        assert_eq!(snap.dimm_locators, vec!["DIMM_A1", "DIMM_B1"]);
        assert_eq!(snap.dimm_sizes_bytes, vec![34_359_738_368, 34_359_738_368]);
    }
}
