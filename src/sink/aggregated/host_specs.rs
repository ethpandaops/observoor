use std::fs;
use std::path::Path;
use std::process::Command;

/// Snapshot of host-level machine specifications.
#[derive(Debug, Clone)]
pub struct HostSpecsSnapshot {
    pub host_id: String,
    pub hostname: String,
    pub machine_id: String,
    pub kernel_release: String,
    pub os_name: String,
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_vendor: String,
    pub cpu_online_cores: u16,
    pub cpu_logical_cores: u16,
    pub memory_total_bytes: u64,
    pub memory_type: String,
    pub memory_speed_mts: u32,
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

    let cpuinfo = read_text_file("/proc/cpuinfo").unwrap_or_default();
    let (cpu_model, cpu_vendor, cpu_logical_cores) = parse_cpuinfo(&cpuinfo);
    let cpu_online_cores = read_cpu_online().unwrap_or(cpu_logical_cores);

    let meminfo = read_text_file("/proc/meminfo").unwrap_or_default();
    let memory_total_bytes = parse_mem_total_bytes(&meminfo).unwrap_or(0);

    let (memory_type, memory_speed_mts) = read_memory_dmi();

    let disks = read_disk_specs();

    let host_id = if !machine_id.is_empty() {
        machine_id.clone()
    } else if !hostname.is_empty() {
        hostname.clone()
    } else {
        "unknown".to_string()
    };

    HostSpecsSnapshot {
        host_id,
        hostname,
        machine_id,
        kernel_release,
        os_name,
        architecture: std::env::consts::ARCH.to_string(),
        cpu_model,
        cpu_vendor,
        cpu_online_cores,
        cpu_logical_cores,
        memory_total_bytes,
        memory_type,
        memory_speed_mts,
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

fn read_memory_dmi() -> (String, u32) {
    let output = Command::new("dmidecode").args(["-t", "memory"]).output();
    let Ok(output) = output else {
        return (String::new(), 0);
    };
    if !output.status.success() {
        return (String::new(), 0);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    parse_dmidecode_memory(&text)
}

fn parse_dmidecode_memory(text: &str) -> (String, u32) {
    let mut memory_type = String::new();
    let mut configured_speed_mts = 0u32;
    let mut speed_mts = 0u32;

    for line in text.lines() {
        let trimmed = line.trim();
        if memory_type.is_empty() {
            if let Some(v) = trimmed.strip_prefix("Type:") {
                let parsed = v.trim();
                if !parsed.is_empty() && parsed != "Unknown" && parsed != "RAM" {
                    memory_type = parsed.to_string();
                }
                continue;
            }
        }

        if let Some(v) = trimmed.strip_prefix("Configured Memory Speed:") {
            configured_speed_mts = parse_speed_mts(v);
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("Speed:") {
            speed_mts = parse_speed_mts(v);
        }
    }

    let memory_speed_mts = if configured_speed_mts > 0 {
        configured_speed_mts
    } else {
        speed_mts
    };

    (memory_type, memory_speed_mts)
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
    fn test_parse_dmidecode_memory() {
        let sample = r#"
Memory Device
	Type: DDR5
	Speed: 5600 MT/s
	Configured Memory Speed: 5200 MT/s
"#;
        let (mem_type, speed) = parse_dmidecode_memory(sample);
        assert_eq!(mem_type, "DDR5");
        assert_eq!(speed, 5200);
    }
}
