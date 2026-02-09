use std::collections::HashMap;
use std::fmt;

use anyhow::Result;
use tracing::debug;

use crate::tracer::event::ClientType;

/// Semantic label for a well-known Ethereum client port.
///
/// Stored as a `u8` discriminant in dimension keys for zero-cost aggregation.
/// Converted to a string label at export time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PortLabel {
    /// Unmapped or unknown port.
    Unknown = 0,

    // -- Execution Layer --
    /// devp2p TCP (default 30303).
    ElP2PTcp = 1,
    /// devp2p discovery UDP (default 30303).
    ElDiscovery = 2,
    /// JSON-RPC HTTP (default 8545).
    ElJsonRpc = 3,
    /// WebSocket RPC (default 8546).
    ElWebSocket = 4,
    /// Engine API / auth RPC (default 8551).
    ElEngineApi = 5,

    // -- Consensus Layer --
    /// libp2p TCP (default 9000/13000).
    ClP2PTcp = 6,
    /// libp2p QUIC (default 9001).
    ClP2PQuic = 7,
    /// discv5 UDP (default 12000).
    ClDiscovery = 8,
    /// Beacon REST API (default 5052/3500/5051/9596).
    ClBeaconApi = 9,
    /// gRPC (Prysm default 4000).
    ClGrpc = 10,
}

impl PortLabel {
    /// Returns the string representation used in ClickHouse and JSON exports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::ElP2PTcp => "el_p2p_tcp",
            Self::ElDiscovery => "el_discovery",
            Self::ElJsonRpc => "el_json_rpc",
            Self::ElWebSocket => "el_ws",
            Self::ElEngineApi => "el_engine_api",
            Self::ClP2PTcp => "cl_p2p_tcp",
            Self::ClP2PQuic => "cl_p2p_quic",
            Self::ClDiscovery => "cl_discovery",
            Self::ClBeaconApi => "cl_beacon_api",
            Self::ClGrpc => "cl_grpc",
        }
    }

    /// Converts a `u8` discriminant back to a `PortLabel`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::ElP2PTcp),
            2 => Some(Self::ElDiscovery),
            3 => Some(Self::ElJsonRpc),
            4 => Some(Self::ElWebSocket),
            5 => Some(Self::ElEngineApi),
            6 => Some(Self::ClP2PTcp),
            7 => Some(Self::ClP2PQuic),
            8 => Some(Self::ClDiscovery),
            9 => Some(Self::ClBeaconApi),
            10 => Some(Self::ClGrpc),
            _ => None,
        }
    }
}

impl fmt::Display for PortLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Discovered port information for a PID.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PortInfo {
    pub pid: u32,
    pub client_type: ClientType,
    pub ports: HashMap<u16, PortLabel>,
}

/// Default well-known ports per client type with semantic labels.
pub fn default_ports(client: ClientType) -> &'static [(u16, PortLabel)] {
    match client {
        // Execution clients.
        ClientType::Geth => &[
            (8545, PortLabel::ElJsonRpc),
            (8546, PortLabel::ElWebSocket),
            (8551, PortLabel::ElEngineApi),
            (30303, PortLabel::ElP2PTcp),
        ],
        ClientType::Reth => &[
            (8545, PortLabel::ElJsonRpc),
            (8546, PortLabel::ElWebSocket),
            (8551, PortLabel::ElEngineApi),
            (30303, PortLabel::ElP2PTcp),
        ],
        ClientType::Besu => &[
            (8545, PortLabel::ElJsonRpc),
            (8546, PortLabel::ElWebSocket),
            (8551, PortLabel::ElEngineApi),
            (30303, PortLabel::ElP2PTcp),
        ],
        ClientType::Nethermind => &[
            (8545, PortLabel::ElJsonRpc),
            (8551, PortLabel::ElEngineApi),
            (30303, PortLabel::ElP2PTcp),
        ],
        ClientType::Erigon => &[
            (8545, PortLabel::ElJsonRpc),
            (8551, PortLabel::ElEngineApi),
            (30303, PortLabel::ElP2PTcp),
        ],
        // Consensus clients.
        ClientType::Lighthouse => &[
            (5052, PortLabel::ClBeaconApi),
            (9000, PortLabel::ClP2PTcp),
            (9001, PortLabel::ClP2PQuic),
        ],
        ClientType::Prysm => &[
            (3500, PortLabel::ClBeaconApi),
            (4000, PortLabel::ClGrpc),
            (13000, PortLabel::ClP2PTcp),
            (12000, PortLabel::ClDiscovery),
        ],
        ClientType::Teku => &[
            (5051, PortLabel::ClBeaconApi),
            (5052, PortLabel::ClBeaconApi),
            (9000, PortLabel::ClP2PTcp),
        ],
        ClientType::Lodestar => &[(9596, PortLabel::ClBeaconApi), (9000, PortLabel::ClP2PTcp)],
        ClientType::Nimbus => &[(5052, PortLabel::ClBeaconApi), (9000, PortLabel::ClP2PTcp)],
        // No defaults for unknown or ethrex.
        _ => &[],
    }
}

/// Known port flags per client type, paired with their semantic label.
fn port_flags(client: ClientType) -> &'static [(&'static str, PortLabel)] {
    match client {
        ClientType::Geth => &[
            ("--http.port", PortLabel::ElJsonRpc),
            ("--ws.port", PortLabel::ElWebSocket),
            ("--authrpc.port", PortLabel::ElEngineApi),
            ("--port", PortLabel::ElP2PTcp),
            ("--discovery.port", PortLabel::ElDiscovery),
        ],
        ClientType::Reth => &[
            ("--http.port", PortLabel::ElJsonRpc),
            ("--ws.port", PortLabel::ElWebSocket),
            ("--authrpc.port", PortLabel::ElEngineApi),
            ("--port", PortLabel::ElP2PTcp),
            ("--discovery.port", PortLabel::ElDiscovery),
            ("--discovery.v5.port", PortLabel::ElDiscovery),
        ],
        ClientType::Erigon => &[
            ("--http.port", PortLabel::ElJsonRpc),
            ("--ws.port", PortLabel::ElWebSocket),
            ("--authrpc.port", PortLabel::ElEngineApi),
            ("--port", PortLabel::ElP2PTcp),
            ("--p2p.port", PortLabel::ElP2PTcp),
        ],
        ClientType::Besu => &[
            ("--rpc-http-port", PortLabel::ElJsonRpc),
            ("--rpc-ws-port", PortLabel::ElWebSocket),
            ("--engine-rpc-port", PortLabel::ElEngineApi),
            ("--p2p-port", PortLabel::ElP2PTcp),
            ("--discovery-port", PortLabel::ElDiscovery),
        ],
        ClientType::Nethermind => &[
            ("--JsonRpc.Port", PortLabel::ElJsonRpc),
            ("--JsonRpc.EnginePort", PortLabel::ElEngineApi),
            ("--Network.P2PPort", PortLabel::ElP2PTcp),
            ("--Network.DiscoveryPort", PortLabel::ElDiscovery),
        ],
        ClientType::Lighthouse => &[
            ("--http-port", PortLabel::ClBeaconApi),
            ("--port", PortLabel::ClP2PTcp),
            ("--discovery-port", PortLabel::ClDiscovery),
            ("--quic-port", PortLabel::ClP2PQuic),
        ],
        ClientType::Prysm => &[
            ("--grpc-gateway-port", PortLabel::ClBeaconApi),
            ("--rpc-port", PortLabel::ClGrpc),
            ("--p2p-tcp-port", PortLabel::ClP2PTcp),
            ("--p2p-udp-port", PortLabel::ClDiscovery),
        ],
        ClientType::Teku => &[
            ("--rest-api-port", PortLabel::ClBeaconApi),
            ("--p2p-port", PortLabel::ClP2PTcp),
            ("--p2p-udp-port", PortLabel::ClDiscovery),
        ],
        ClientType::Lodestar => &[
            ("--rest.port", PortLabel::ClBeaconApi),
            ("--port", PortLabel::ClP2PTcp),
            ("--discoveryPort", PortLabel::ClDiscovery),
        ],
        ClientType::Nimbus => &[
            ("--rest-port", PortLabel::ClBeaconApi),
            ("--tcp-port", PortLabel::ClP2PTcp),
            ("--udp-port", PortLabel::ClDiscovery),
        ],
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

        let mut ports = HashMap::with_capacity(8);

        // Try to parse ports from cmdline.
        match read_proc_cmdline(pid) {
            Ok(cmdline) => {
                let parsed = parse_ports_from_cmdline(&cmdline, client_type);
                for (port, label) in parsed {
                    ports.insert(port, label);
                }
            }
            Err(e) => {
                debug!(pid, error = %e, "failed to read cmdline for port discovery");
            }
        }

        // Fall back to defaults if no ports found.
        if ports.is_empty() {
            let defaults = default_ports(client_type);
            for &(port, label) in defaults {
                ports.insert(port, label);
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

/// Collect all port-to-label mappings across all PIDs.
pub fn all_port_labels(port_infos: &HashMap<u32, PortInfo>) -> HashMap<u16, PortLabel> {
    let mut result = HashMap::with_capacity(32);

    for info in port_infos.values() {
        for (&port, &label) in &info.ports {
            result.insert(port, label);
        }
    }

    result
}

/// Parse port numbers from a cmdline string using known flag patterns.
fn parse_ports_from_cmdline(cmdline: &str, client_type: ClientType) -> Vec<(u16, PortLabel)> {
    let flags = port_flags(client_type);
    if flags.is_empty() && client_type != ClientType::Unknown {
        return Vec::new();
    }

    let args: Vec<&str> = cmdline.split_whitespace().collect();
    let mut ports = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        for &(flag, label) in flags {
            // --flag=value format.
            let prefix = format!("{flag}=");
            if let Some(value) = arg.strip_prefix(&prefix) {
                if let Some(port) = parse_port(value) {
                    ports.push((port, label));
                }
                continue;
            }

            // --flag value format.
            if *arg == flag {
                if let Some(next) = args.get(i + 1) {
                    if let Some(port) = parse_port(next) {
                        ports.push((port, label));
                    }
                }
            }
        }
    }

    // Regex fallback for unknown clients.
    if client_type == ClientType::Unknown {
        for port in find_port_patterns(cmdline) {
            ports.push((port, PortLabel::Unknown));
        }
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
    fn test_port_label_as_str() {
        assert_eq!(PortLabel::Unknown.as_str(), "unknown");
        assert_eq!(PortLabel::ElP2PTcp.as_str(), "el_p2p_tcp");
        assert_eq!(PortLabel::ElJsonRpc.as_str(), "el_json_rpc");
        assert_eq!(PortLabel::ClBeaconApi.as_str(), "cl_beacon_api");
        assert_eq!(PortLabel::ClGrpc.as_str(), "cl_grpc");
    }

    #[test]
    fn test_port_label_from_u8_roundtrip() {
        for v in 0..=10u8 {
            let label = PortLabel::from_u8(v).expect("valid discriminant");
            assert_eq!(label as u8, v);
        }
        assert!(PortLabel::from_u8(11).is_none());
        assert!(PortLabel::from_u8(255).is_none());
    }

    #[test]
    fn test_port_label_display() {
        assert_eq!(format!("{}", PortLabel::ElEngineApi), "el_engine_api");
    }

    #[test]
    fn test_default_ports_geth() {
        let ports = default_ports(ClientType::Geth);
        let map: HashMap<u16, PortLabel> = ports.iter().copied().collect();
        assert_eq!(map.get(&8545), Some(&PortLabel::ElJsonRpc));
        assert_eq!(map.get(&8546), Some(&PortLabel::ElWebSocket));
        assert_eq!(map.get(&8551), Some(&PortLabel::ElEngineApi));
        assert_eq!(map.get(&30303), Some(&PortLabel::ElP2PTcp));
        assert_eq!(ports.len(), 4);
    }

    #[test]
    fn test_default_ports_lighthouse() {
        let ports = default_ports(ClientType::Lighthouse);
        let map: HashMap<u16, PortLabel> = ports.iter().copied().collect();
        assert_eq!(map.get(&5052), Some(&PortLabel::ClBeaconApi));
        assert_eq!(map.get(&9000), Some(&PortLabel::ClP2PTcp));
        assert_eq!(map.get(&9001), Some(&PortLabel::ClP2PQuic));
    }

    #[test]
    fn test_default_ports_prysm() {
        let ports = default_ports(ClientType::Prysm);
        let map: HashMap<u16, PortLabel> = ports.iter().copied().collect();
        assert_eq!(map.get(&3500), Some(&PortLabel::ClBeaconApi));
        assert_eq!(map.get(&4000), Some(&PortLabel::ClGrpc));
        assert_eq!(map.get(&13000), Some(&PortLabel::ClP2PTcp));
        assert_eq!(map.get(&12000), Some(&PortLabel::ClDiscovery));
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
        assert_eq!(
            ports,
            vec![
                (8545, PortLabel::ElJsonRpc),
                (8546, PortLabel::ElWebSocket),
                (8551, PortLabel::ElEngineApi),
                (30303, PortLabel::ElP2PTcp),
            ]
        );
    }

    #[test]
    fn test_parse_ports_geth_space_format() {
        let cmdline = "geth --http.port 8545 --port 30303";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Geth);
        assert_eq!(
            ports,
            vec![(8545, PortLabel::ElJsonRpc), (30303, PortLabel::ElP2PTcp),]
        );
    }

    #[test]
    fn test_parse_ports_lighthouse() {
        let cmdline = "lighthouse bn --http-port=5052 --port=9000 --discovery-port=9000";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Lighthouse);
        assert_eq!(
            ports,
            vec![
                (5052, PortLabel::ClBeaconApi),
                (9000, PortLabel::ClP2PTcp),
                (9000, PortLabel::ClDiscovery),
            ]
        );
    }

    #[test]
    fn test_parse_ports_prysm() {
        let cmdline = "beacon-chain --grpc-gateway-port 3500 --rpc-port 4000 --p2p-tcp-port 13000";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Prysm);
        assert_eq!(
            ports,
            vec![
                (3500, PortLabel::ClBeaconApi),
                (4000, PortLabel::ClGrpc),
                (13000, PortLabel::ClP2PTcp),
            ]
        );
    }

    #[test]
    fn test_parse_ports_unknown_client_regex() {
        let cmdline = "some_process --listen-port=9999 --other-port 1234";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Unknown);
        let port_nums: Vec<u16> = ports.iter().map(|(p, _)| *p).collect();
        assert!(port_nums.contains(&9999));
        assert!(port_nums.contains(&1234));
        // Unknown client ports get Unknown label.
        for (_, label) in &ports {
            assert_eq!(*label, PortLabel::Unknown);
        }
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
    fn test_all_port_labels() {
        let mut infos = HashMap::new();
        let mut ports1 = HashMap::new();
        ports1.insert(8545, PortLabel::ElJsonRpc);
        ports1.insert(30303, PortLabel::ElP2PTcp);
        infos.insert(
            1,
            PortInfo {
                pid: 1,
                client_type: ClientType::Geth,
                ports: ports1,
            },
        );

        let mut ports2 = HashMap::new();
        ports2.insert(5052, PortLabel::ClBeaconApi);
        ports2.insert(9000, PortLabel::ClP2PTcp);
        infos.insert(
            2,
            PortInfo {
                pid: 2,
                client_type: ClientType::Lighthouse,
                ports: ports2,
            },
        );

        let all = all_port_labels(&infos);
        assert_eq!(all.len(), 4);
        assert_eq!(all.get(&8545), Some(&PortLabel::ElJsonRpc));
        assert_eq!(all.get(&30303), Some(&PortLabel::ElP2PTcp));
        assert_eq!(all.get(&5052), Some(&PortLabel::ClBeaconApi));
        assert_eq!(all.get(&9000), Some(&PortLabel::ClP2PTcp));
    }
}
