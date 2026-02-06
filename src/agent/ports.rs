use std::collections::{HashMap, HashSet};

use anyhow::Result;
use tracing::debug;

use crate::tracer::event::ClientType;

/// Discovered port information for a PID.
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub pid: u32,
    pub client_type: ClientType,
    pub ports: HashSet<u16>,
}

/// Default well-known ports per client type.
pub fn default_ports(client: ClientType) -> &'static [u16] {
    match client {
        // Execution clients.
        ClientType::Geth => &[8545, 8546, 8551, 30303],
        ClientType::Reth => &[8545, 8546, 8551, 30303],
        ClientType::Besu => &[8545, 8546, 8551, 30303],
        ClientType::Nethermind => &[8545, 8551, 30303],
        ClientType::Erigon => &[8545, 8551, 30303],
        // Consensus clients.
        ClientType::Lighthouse => &[5052, 9000, 9001],
        ClientType::Prysm => &[3500, 4000, 13000, 12000],
        ClientType::Teku => &[5051, 5052, 9000],
        ClientType::Lodestar => &[9596, 9000],
        ClientType::Nimbus => &[5052, 9000],
        // No defaults for unknown or ethrex.
        _ => &[],
    }
}

/// Known port flags per client type.
fn port_flags(client: ClientType) -> &'static [&'static str] {
    match client {
        ClientType::Geth => &[
            "--http.port",
            "--ws.port",
            "--authrpc.port",
            "--port",
            "--discovery.port",
        ],
        ClientType::Reth => &[
            "--http.port",
            "--ws.port",
            "--authrpc.port",
            "--port",
            "--discovery.port",
            "--discovery.v5.port",
        ],
        ClientType::Erigon => &[
            "--http.port",
            "--ws.port",
            "--authrpc.port",
            "--port",
            "--p2p.port",
        ],
        ClientType::Besu => &[
            "--rpc-http-port",
            "--rpc-ws-port",
            "--engine-rpc-port",
            "--p2p-port",
            "--discovery-port",
        ],
        ClientType::Nethermind => &[
            "--JsonRpc.Port",
            "--JsonRpc.EnginePort",
            "--Network.P2PPort",
            "--Network.DiscoveryPort",
        ],
        ClientType::Lighthouse => &["--http-port", "--port", "--discovery-port", "--quic-port"],
        ClientType::Prysm => &[
            "--grpc-gateway-port",
            "--rpc-port",
            "--p2p-tcp-port",
            "--p2p-udp-port",
        ],
        ClientType::Teku => &["--rest-api-port", "--p2p-port", "--p2p-udp-port"],
        ClientType::Lodestar => &["--rest.port", "--port", "--discoveryPort"],
        ClientType::Nimbus => &["--rest-port", "--tcp-port", "--udp-port"],
        _ => &[],
    }
}

/// Discover ports for each PID by parsing their command lines.
/// Falls back to default ports when parsing yields nothing.
pub fn discover_ports(
    pids: &[u32],
    client_types: &HashMap<u32, ClientType>,
) -> HashMap<u32, PortInfo> {
    let mut result = HashMap::with_capacity(pids.len());

    for &pid in pids {
        let client_type = client_types
            .get(&pid)
            .copied()
            .unwrap_or(ClientType::Unknown);

        let mut ports = HashSet::with_capacity(8);

        // Try to parse ports from cmdline.
        match read_proc_cmdline(pid) {
            Ok(cmdline) => {
                let parsed = parse_ports_from_cmdline(&cmdline, client_type);
                for port in parsed {
                    ports.insert(port);
                }
            }
            Err(e) => {
                debug!(pid, error = %e, "failed to read cmdline for port discovery");
            }
        }

        // Fall back to defaults if no ports found.
        if ports.is_empty() {
            let defaults = default_ports(client_type);
            for &port in defaults {
                ports.insert(port);
            }

            if !defaults.is_empty() {
                debug!(
                    pid,
                    client = %client_type,
                    ports = ?defaults,
                    "using default ports",
                );
            }
        } else {
            debug!(
                pid,
                client = %client_type,
                ports = ?ports,
                "discovered ports from cmdline",
            );
        }

        result.insert(
            pid,
            PortInfo {
                pid,
                client_type,
                ports,
            },
        );
    }

    result
}

/// Collect all unique ports across all PIDs.
pub fn all_tracked_ports(port_infos: &HashMap<u32, PortInfo>) -> HashSet<u16> {
    let mut result = HashSet::with_capacity(32);

    for info in port_infos.values() {
        for &port in &info.ports {
            result.insert(port);
        }
    }

    result
}

/// Parse port numbers from a cmdline string using known flag patterns.
fn parse_ports_from_cmdline(cmdline: &str, client_type: ClientType) -> Vec<u16> {
    let flags = port_flags(client_type);
    if flags.is_empty() && client_type != ClientType::Unknown {
        return Vec::new();
    }

    let args: Vec<&str> = cmdline.split_whitespace().collect();
    let mut ports = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        for &flag in flags {
            // --flag=value format.
            let prefix = format!("{flag}=");
            if let Some(value) = arg.strip_prefix(&prefix) {
                if let Some(port) = parse_port(value) {
                    ports.push(port);
                }
                continue;
            }

            // --flag value format.
            if *arg == flag {
                if let Some(next) = args.get(i + 1) {
                    if let Some(port) = parse_port(next) {
                        ports.push(port);
                    }
                }
            }
        }
    }

    // Regex fallback for unknown clients.
    if client_type == ClientType::Unknown {
        ports.extend(find_port_patterns(cmdline));
    }

    ports
}

/// Parse a string as a port number (1-65535).
fn parse_port(s: &str) -> Option<u16> {
    let s = s.trim_end_matches([',', ';', ')', ']', '}']);
    let s = s.trim();

    let port: u64 = s.parse().ok()?;

    if (1..=65535).contains(&port) {
        Some(port as u16)
    } else {
        None
    }
}

/// Find port-like patterns in cmdline text (case-insensitive).
fn find_port_patterns(cmdline: &str) -> Vec<u16> {
    // Match patterns like "port=1234", "PORT: 1234", "port 1234".
    let mut ports = Vec::new();
    let lower = cmdline.to_lowercase();
    let bytes = lower.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        // Look for "port" keyword.
        if i + 4 <= bytes.len() && &lower[i..i + 4] == "port" {
            let mut j = i + 4;
            // Skip separators: =, :, space.
            while j < bytes.len() && matches!(bytes.get(j), Some(b'=' | b':' | b' ')) {
                j += 1;
            }
            // Try to read digits.
            let start = j;
            while j < bytes.len() && bytes.get(j).is_some_and(|b| b.is_ascii_digit()) {
                j += 1;
            }
            if j > start {
                if let Some(port) = parse_port(&lower[start..j]) {
                    ports.push(port);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }

    ports
}

/// Read /proc/<pid>/cmdline and join null-separated args with spaces.
#[cfg(target_os = "linux")]
fn read_proc_cmdline(pid: u32) -> Result<String> {
    use anyhow::Context;

    let path = format!("/proc/{pid}/cmdline");
    let data = std::fs::read(&path).with_context(|| format!("reading {path}"))?;
    Ok(String::from_utf8_lossy(&data).replace('\0', " "))
}

#[cfg(not(target_os = "linux"))]
fn read_proc_cmdline(_pid: u32) -> Result<String> {
    anyhow::bail!("port discovery via /proc is only supported on Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports_geth() {
        let ports = default_ports(ClientType::Geth);
        assert_eq!(ports, &[8545, 8546, 8551, 30303]);
    }

    #[test]
    fn test_default_ports_lighthouse() {
        let ports = default_ports(ClientType::Lighthouse);
        assert_eq!(ports, &[5052, 9000, 9001]);
    }

    #[test]
    fn test_default_ports_prysm() {
        let ports = default_ports(ClientType::Prysm);
        assert_eq!(ports, &[3500, 4000, 13000, 12000]);
    }

    #[test]
    fn test_default_ports_unknown() {
        let ports = default_ports(ClientType::Unknown);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_port_valid() {
        assert_eq!(parse_port("8545"), Some(8545));
        assert_eq!(parse_port("30303"), Some(30303));
        assert_eq!(parse_port("1"), Some(1));
        assert_eq!(parse_port("65535"), Some(65535));
    }

    #[test]
    fn test_parse_port_with_trailing_chars() {
        assert_eq!(parse_port("8545,"), Some(8545));
        assert_eq!(parse_port("8545)"), Some(8545));
        assert_eq!(parse_port("8545]"), Some(8545));
    }

    #[test]
    fn test_parse_port_invalid() {
        assert_eq!(parse_port("0"), None);
        assert_eq!(parse_port("65536"), None);
        assert_eq!(parse_port("abc"), None);
        assert_eq!(parse_port(""), None);
    }

    #[test]
    fn test_parse_ports_geth_equals_format() {
        let cmdline = "geth --http.port=8545 --ws.port=8546 --authrpc.port=8551 --port=30303";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Geth);
        assert_eq!(ports, vec![8545, 8546, 8551, 30303]);
    }

    #[test]
    fn test_parse_ports_geth_space_format() {
        let cmdline = "geth --http.port 8545 --port 30303";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Geth);
        assert_eq!(ports, vec![8545, 30303]);
    }

    #[test]
    fn test_parse_ports_lighthouse() {
        let cmdline = "lighthouse bn --http-port=5052 --port=9000 --discovery-port=9000";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Lighthouse);
        assert_eq!(ports, vec![5052, 9000, 9000]);
    }

    #[test]
    fn test_parse_ports_prysm() {
        let cmdline = "beacon-chain --grpc-gateway-port 3500 --rpc-port 4000 --p2p-tcp-port 13000";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Prysm);
        assert_eq!(ports, vec![3500, 4000, 13000]);
    }

    #[test]
    fn test_parse_ports_unknown_client_regex() {
        let cmdline = "some_process --listen-port=9999 --other-port 1234";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Unknown);
        assert!(ports.contains(&9999));
        assert!(ports.contains(&1234));
    }

    #[test]
    fn test_find_port_patterns() {
        let cmdline = "--listen-port=8080 --other PORT: 9090 rest-port 3000";
        let ports = find_port_patterns(cmdline);
        assert!(ports.contains(&8080));
        assert!(ports.contains(&9090));
        assert!(ports.contains(&3000));
    }

    #[test]
    fn test_all_tracked_ports() {
        let mut infos = HashMap::new();
        let mut ports1 = HashSet::new();
        ports1.insert(8545);
        ports1.insert(30303);
        infos.insert(
            1,
            PortInfo {
                pid: 1,
                client_type: ClientType::Geth,
                ports: ports1,
            },
        );

        let mut ports2 = HashSet::new();
        ports2.insert(5052);
        ports2.insert(9000);
        infos.insert(
            2,
            PortInfo {
                pid: 2,
                client_type: ClientType::Lighthouse,
                ports: ports2,
            },
        );

        let all = all_tracked_ports(&infos);
        assert_eq!(all.len(), 4);
        assert!(all.contains(&8545));
        assert!(all.contains(&30303));
        assert!(all.contains(&5052));
        assert!(all.contains(&9000));
    }
}
