use std::collections::HashMap;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "linux")]
use tracing::debug;
use tracing::warn;

use crate::config::PidConfig;
use crate::tracer::event::ClientType;

/// Default process names for all known Ethereum client binaries.
pub const DEFAULT_PROCESS_NAMES: &[&str] = &[
    // Execution layer
    "geth",
    "reth",
    "besu",
    "nethermind",
    "erigon",
    "ethrex",
    // Consensus layer
    "lighthouse",
    "prysm",
    "beacon-chain",
    "validator",
    "teku",
    "lodestar",
    "nimbus",
    "nimbus_beacon_n",
    "grandine",
    // Generic runtimes (client type resolved via cmdline)
    "java",
    "node",
    "MainThread",
];

pub use crate::tracer::TrackedTidInfo;

/// PID discovery trait.
pub trait Discovery: Send + Sync {
    /// Discover PIDs matching the configured criteria.
    fn discover(&self) -> Result<Vec<u32>>;
}

/// Composite PID discovery combining process-name and cgroup scanning.
pub struct CompositeDiscovery {
    process_names: Vec<String>,
    cgroup_path: String,
}

impl CompositeDiscovery {
    /// Create a new composite discovery from config.
    pub fn new(cfg: &PidConfig) -> Self {
        let process_names = if cfg.process_names.is_empty() && cfg.cgroup_path.is_empty() {
            DEFAULT_PROCESS_NAMES
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            cfg.process_names.clone()
        };

        Self {
            process_names,
            cgroup_path: cfg.cgroup_path.clone(),
        }
    }
}

impl Discovery for CompositeDiscovery {
    #[cfg(target_os = "linux")]
    fn discover(&self) -> Result<Vec<u32>> {
        use std::collections::HashSet;

        let mut seen = HashSet::with_capacity(64);
        let mut result = Vec::with_capacity(64);

        if !self.process_names.is_empty() {
            match discover_by_process_name(&self.process_names) {
                Ok(pids) => {
                    for pid in pids {
                        if seen.insert(pid) {
                            result.push(pid);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "process name discovery failed");
                }
            }
        }

        if !self.cgroup_path.is_empty() {
            match discover_by_cgroup(&self.cgroup_path) {
                Ok(pids) => {
                    for pid in pids {
                        if seen.insert(pid) {
                            result.push(pid);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "cgroup discovery failed");
                }
            }
        }

        if result.is_empty() {
            warn!("no PIDs discovered");
        } else {
            debug!(count = result.len(), "discovered PIDs");
        }

        Ok(result)
    }

    #[cfg(not(target_os = "linux"))]
    fn discover(&self) -> Result<Vec<u32>> {
        warn!("PID discovery is only supported on Linux");
        Ok(Vec::new())
    }
}

/// Scan /proc for processes matching the given names.
#[cfg(target_os = "linux")]
fn discover_by_process_name(names: &[String]) -> Result<Vec<u32>> {
    use std::collections::HashSet;
    use std::fs;

    let name_set: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();

    let entries = fs::read_dir("/proc").context("reading /proc")?;

    let mut pids = Vec::with_capacity(16);

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm = match read_proc_comm(pid) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if name_set.contains(comm.as_str())
            || comm
                .strip_suffix("-binary")
                .is_some_and(|base| name_set.contains(base))
        {
            debug!(pid, comm = %comm, "found matching process");
            pids.push(pid);
        }
    }

    Ok(pids)
}

/// Read PIDs from a cgroup v2 cgroup.procs file.
#[cfg(target_os = "linux")]
fn discover_by_cgroup(cgroup_path: &str) -> Result<Vec<u32>> {
    use std::fs;
    use std::path::Path;

    let procs_path = Path::new(cgroup_path).join("cgroup.procs");
    let content = fs::read_to_string(&procs_path)
        .with_context(|| format!("reading {}", procs_path.display()))?;

    let mut pids = Vec::with_capacity(16);

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match line.parse::<u32>() {
            Ok(pid) => {
                debug!(pid, "found PID in cgroup");
                pids.push(pid);
            }
            Err(_) => {
                warn!(line, "non-numeric line in cgroup.procs");
            }
        }
    }

    Ok(pids)
}

/// Resolve the ClientType for a given PID.
#[cfg(target_os = "linux")]
pub fn resolve_client_type(pid: u32) -> ClientType {
    // Step 1: Try /proc/<pid>/comm lookup.
    if let Ok(comm) = read_proc_comm(pid) {
        if let Some(ct) = client_type_from_comm(&comm) {
            return ct;
        }

        // Step 2: Fallback to cmdline keyword search.
        if let Ok(cmdline) = read_proc_cmdline(pid) {
            if let Some(ct) = client_type_from_cmdline(&cmdline) {
                return ct;
            }
        }
    }

    ClientType::Unknown
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_client_type(_pid: u32) -> ClientType {
    ClientType::Unknown
}

/// Resolve client types for a batch of PIDs.
pub fn resolve_client_types(pids: &[u32]) -> HashMap<u32, ClientType> {
    let mut types = HashMap::with_capacity(pids.len());

    for &pid in pids {
        types.insert(pid, resolve_client_type(pid));
    }

    types
}

/// Discover all TIDs for the given PIDs, mapping each to its TrackedTidInfo.
#[cfg(target_os = "linux")]
pub fn discover_tids(
    pids: &[u32],
    client_types: &HashMap<u32, ClientType>,
) -> (Vec<u32>, HashMap<u32, TrackedTidInfo>) {
    use std::fs;

    let mut tids = Vec::with_capacity(pids.len() * 64);
    let mut tid_info = HashMap::with_capacity(pids.len() * 64);

    for &pid in pids {
        let ct = client_types
            .get(&pid)
            .copied()
            .unwrap_or(ClientType::Unknown);
        let task_dir = format!("/proc/{pid}/task");

        let entries = match fs::read_dir(&task_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!(pid, error = %e, "failed to read task directory");
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let tid: u32 = match entry.file_name().to_string_lossy().parse() {
                Ok(t) => t,
                Err(_) => continue,
            };

            tids.push(tid);
            tid_info.insert(tid, TrackedTidInfo { pid, client: ct });
        }
    }

    (tids, tid_info)
}

#[cfg(not(target_os = "linux"))]
pub fn discover_tids(
    _pids: &[u32],
    _client_types: &HashMap<u32, ClientType>,
) -> (Vec<u32>, HashMap<u32, TrackedTidInfo>) {
    (Vec::new(), HashMap::new())
}

/// Map comm name to ClientType.
fn client_type_from_comm(comm: &str) -> Option<ClientType> {
    let normalized = comm.strip_suffix("-binary").unwrap_or(comm);

    match normalized {
        "geth" => Some(ClientType::Geth),
        "reth" => Some(ClientType::Reth),
        "besu" => Some(ClientType::Besu),
        "nethermind" => Some(ClientType::Nethermind),
        "erigon" => Some(ClientType::Erigon),
        "ethrex" => Some(ClientType::Ethrex),
        "prysm" | "beacon-chain" | "validator" => Some(ClientType::Prysm),
        "lighthouse" => Some(ClientType::Lighthouse),
        "teku" => Some(ClientType::Teku),
        "lodestar" => Some(ClientType::Lodestar),
        "nimbus" | "nimbus_beacon_n" => Some(ClientType::Nimbus),
        "grandine" => Some(ClientType::Grandine),
        _ => None,
    }
}

/// Search cmdline for client keywords (case-insensitive).
fn client_type_from_cmdline(cmdline: &str) -> Option<ClientType> {
    let lower = cmdline.to_lowercase();

    // Order matters: check more specific first.
    if lower.contains("teku") {
        return Some(ClientType::Teku);
    }
    if lower.contains("besu") {
        return Some(ClientType::Besu);
    }
    if lower.contains("lodestar") {
        return Some(ClientType::Lodestar);
    }
    if lower.contains("nimbus") {
        return Some(ClientType::Nimbus);
    }
    if lower.contains("grandine") {
        return Some(ClientType::Grandine);
    }
    if lower.contains("ethrex") {
        return Some(ClientType::Ethrex);
    }
    if lower.contains("lighthouse") {
        return Some(ClientType::Lighthouse);
    }
    if lower.contains("prysm") || lower.contains("beacon-chain") {
        return Some(ClientType::Prysm);
    }
    if lower.contains("nethermind") {
        return Some(ClientType::Nethermind);
    }
    if lower.contains("erigon") {
        return Some(ClientType::Erigon);
    }
    if lower.contains("reth") {
        return Some(ClientType::Reth);
    }
    if lower.contains("geth") {
        return Some(ClientType::Geth);
    }

    None
}

/// Read /proc/<pid>/comm, returning the trimmed process name.
#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/comm");
    let data = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    Ok(data.trim().to_string())
}

/// Read /proc/<pid>/cmdline, joining null-separated args with spaces.
#[cfg(target_os = "linux")]
fn read_proc_cmdline(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/cmdline");
    let data = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
    Ok(String::from_utf8_lossy(&data).replace('\0', " "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_type_from_comm_known() {
        assert_eq!(client_type_from_comm("geth"), Some(ClientType::Geth));
        assert_eq!(client_type_from_comm("reth"), Some(ClientType::Reth));
        assert_eq!(client_type_from_comm("reth-binary"), Some(ClientType::Reth));
        assert_eq!(client_type_from_comm("besu"), Some(ClientType::Besu));
        assert_eq!(
            client_type_from_comm("nethermind"),
            Some(ClientType::Nethermind)
        );
        assert_eq!(client_type_from_comm("erigon"), Some(ClientType::Erigon));
        assert_eq!(client_type_from_comm("ethrex"), Some(ClientType::Ethrex));
        assert_eq!(client_type_from_comm("prysm"), Some(ClientType::Prysm));
        assert_eq!(
            client_type_from_comm("beacon-chain"),
            Some(ClientType::Prysm)
        );
        assert_eq!(client_type_from_comm("validator"), Some(ClientType::Prysm));
        assert_eq!(
            client_type_from_comm("lighthouse"),
            Some(ClientType::Lighthouse)
        );
        assert_eq!(client_type_from_comm("teku"), Some(ClientType::Teku));
        assert_eq!(
            client_type_from_comm("lodestar"),
            Some(ClientType::Lodestar)
        );
        assert_eq!(client_type_from_comm("nimbus"), Some(ClientType::Nimbus));
        assert_eq!(
            client_type_from_comm("nimbus_beacon_n"),
            Some(ClientType::Nimbus)
        );
        assert_eq!(
            client_type_from_comm("grandine"),
            Some(ClientType::Grandine)
        );
    }

    #[test]
    fn test_client_type_from_comm_unknown() {
        assert_eq!(client_type_from_comm("java"), None);
        assert_eq!(client_type_from_comm("node"), None);
        assert_eq!(client_type_from_comm("unknown_process"), None);
    }

    #[test]
    fn test_client_type_from_cmdline_matches() {
        assert_eq!(
            client_type_from_cmdline("/usr/bin/java -jar teku.jar"),
            Some(ClientType::Teku),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/bin/java -jar Besu.jar"),
            Some(ClientType::Besu),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/bin/node lodestar beacon"),
            Some(ClientType::Lodestar),
        );
        assert_eq!(
            client_type_from_cmdline("nimbus_beacon_node --data-dir=/data"),
            Some(ClientType::Nimbus),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/bin/grandine --network mainnet"),
            Some(ClientType::Grandine),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/bin/ethrex --config=foo"),
            Some(ClientType::Ethrex),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/local/bin/reth-binary node --chain=/network-configs/genesis.json"),
            Some(ClientType::Reth),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/bin/geth --datadir=/data/geth"),
            Some(ClientType::Geth),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/local/bin/beacon-chain --grpc-gateway-host=0.0.0.0"),
            Some(ClientType::Prysm),
        );
        assert_eq!(
            client_type_from_cmdline("/usr/bin/lighthouse bn --network mainnet"),
            Some(ClientType::Lighthouse),
        );
    }

    #[test]
    fn test_client_type_from_cmdline_no_match() {
        assert_eq!(client_type_from_cmdline("/usr/bin/python3 script.py"), None);
        assert_eq!(client_type_from_cmdline(""), None);
    }

    #[test]
    fn test_default_process_names_count() {
        assert_eq!(DEFAULT_PROCESS_NAMES.len(), 18);
    }

    #[test]
    fn test_composite_discovery_uses_defaults_when_empty() {
        let cfg = PidConfig {
            process_names: Vec::new(),
            cgroup_path: String::new(),
        };
        let disc = CompositeDiscovery::new(&cfg);
        assert_eq!(disc.process_names.len(), DEFAULT_PROCESS_NAMES.len());
    }

    #[test]
    fn test_composite_discovery_uses_configured_names() {
        let cfg = PidConfig {
            process_names: vec!["geth".to_string(), "reth".to_string()],
            cgroup_path: String::new(),
        };
        let disc = CompositeDiscovery::new(&cfg);
        assert_eq!(disc.process_names.len(), 2);
        assert_eq!(disc.process_names[0], "geth");
        assert_eq!(disc.process_names[1], "reth");
    }
}
