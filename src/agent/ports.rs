use std::collections::HashMap;
use std::fmt;

use anyhow::Result;
use tracing::debug;

use crate::tracer::event::ClientType;

/// Transport for a labeled service port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortTransport {
    Any,
    Tcp,
    Udp,
}

impl PortTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    const fn sort_key(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Tcp => 1,
            Self::Udp => 2,
        }
    }
}

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
    /// discv5 UDP (default 12000/9000).
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
            Self::ElP2PTcp => "el_p2p",
            Self::ElDiscovery => "el_discovery",
            Self::ElJsonRpc => "el_json_rpc",
            Self::ElWebSocket => "el_ws",
            Self::ElEngineApi => "el_engine_api",
            Self::ClP2PTcp => "cl_p2p",
            Self::ClP2PQuic => "cl_p2p",
            Self::ClDiscovery => "cl_discovery",
            Self::ClBeaconApi => "cl_beacon_api",
            Self::ClGrpc => "cl_grpc",
        }
    }

    /// Returns the expected transport for this label.
    pub const fn transport(self) -> PortTransport {
        match self {
            Self::Unknown => PortTransport::Any,
            Self::ElDiscovery | Self::ClP2PQuic | Self::ClDiscovery => PortTransport::Udp,
            _ => PortTransport::Tcp,
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

#[derive(Debug, Clone, Copy, Default)]
struct PortTransportLabels {
    any: Option<PortLabel>,
    tcp: Option<PortLabel>,
    udp: Option<PortLabel>,
}

impl PortTransportLabels {
    fn set(&mut self, transport: PortTransport, label: PortLabel) {
        match transport {
            PortTransport::Any => upsert_slot(&mut self.any, label),
            PortTransport::Tcp => upsert_slot(&mut self.tcp, label),
            PortTransport::Udp => upsert_slot(&mut self.udp, label),
        }
    }

    fn get(&self, transport: PortTransport) -> Option<PortLabel> {
        match transport {
            PortTransport::Any => self.any,
            PortTransport::Tcp => self.tcp.or(self.any),
            PortTransport::Udp => self.udp.or(self.any),
        }
    }
}

fn upsert_slot(slot: &mut Option<PortLabel>, incoming: PortLabel) {
    match *slot {
        Some(existing) if existing == incoming => {}
        Some(PortLabel::Unknown) => *slot = Some(incoming),
        Some(_) if incoming == PortLabel::Unknown => {}
        Some(_) => {}
        None => *slot = Some(incoming),
    }
}

fn upsert_port_label(port_labels: &mut Vec<(u16, PortLabel)>, port: u16, label: PortLabel) {
    let transport = label.transport();
    if let Some((_, existing_label)) =
        port_labels
            .iter_mut()
            .find(|(existing_port, existing_label)| {
                *existing_port == port && existing_label.transport() == transport
            })
    {
        *existing_label = label;
    } else {
        port_labels.push((port, label));
    }
}

/// Client-aware runtime map for semantic port labels.
#[derive(Debug, Clone, Default)]
pub struct PortLabelMap {
    by_client: HashMap<ClientType, HashMap<u16, PortTransportLabels>>,
    global: HashMap<u16, PortTransportLabels>,
}

impl PortLabelMap {
    pub fn is_empty(&self) -> bool {
        self.by_client.is_empty()
    }

    /// Inserts a label for `(client_type, port, transport)`.
    pub fn insert(&mut self, client_type: ClientType, port: u16, label: PortLabel) {
        let transport = label.transport();

        let client_map = self.by_client.entry(client_type).or_default();
        client_map.entry(port).or_default().set(transport, label);

        self.global.entry(port).or_default().set(transport, label);
    }

    /// Resolve a TCP label for this client, preferring `primary_port` then `secondary_port`.
    pub fn resolve_tcp(
        &self,
        client_type: ClientType,
        primary_port: u16,
        secondary_port: u16,
    ) -> PortLabel {
        self.resolve(
            client_type,
            PortTransport::Tcp,
            primary_port,
            secondary_port,
        )
    }

    /// Resolve a UDP label for this client, preferring `primary_port` then `secondary_port`.
    pub fn resolve_udp(
        &self,
        client_type: ClientType,
        primary_port: u16,
        secondary_port: u16,
    ) -> PortLabel {
        self.resolve(
            client_type,
            PortTransport::Udp,
            primary_port,
            secondary_port,
        )
    }

    /// Flatten mappings for structured logging/debugging.
    pub fn mappings(&self) -> Vec<(ClientType, u16, PortTransport, PortLabel)> {
        let mut out = Vec::with_capacity(64);

        for (&client_type, ports) in &self.by_client {
            for (&port, labels) in ports {
                if let Some(label) = labels.tcp {
                    out.push((client_type, port, PortTransport::Tcp, label));
                }
                if let Some(label) = labels.udp {
                    out.push((client_type, port, PortTransport::Udp, label));
                }
                if let Some(label) = labels.any {
                    out.push((client_type, port, PortTransport::Any, label));
                }
            }
        }

        out.sort_unstable_by_key(|(client_type, port, transport, label)| {
            (
                *client_type as u8,
                *port,
                transport.sort_key(),
                *label as u8,
            )
        });
        out
    }

    fn resolve(
        &self,
        client_type: ClientType,
        transport: PortTransport,
        primary_port: u16,
        secondary_port: u16,
    ) -> PortLabel {
        let candidates = [primary_port, secondary_port];

        if let Some(label) = self.resolve_from_client(client_type, transport, &candidates) {
            return label;
        }

        if client_type != ClientType::Unknown {
            if let Some(label) =
                self.resolve_from_client(ClientType::Unknown, transport, &candidates)
            {
                return label;
            }
        }

        if client_type == ClientType::Unknown {
            for port in candidates {
                if let Some(label) = self
                    .global
                    .get(&port)
                    .and_then(|labels| labels.get(transport))
                {
                    return label;
                }
            }
        }

        PortLabel::Unknown
    }

    fn resolve_from_client(
        &self,
        client_type: ClientType,
        transport: PortTransport,
        candidates: &[u16; 2],
    ) -> Option<PortLabel> {
        let client_map = self.by_client.get(&client_type)?;

        for port in candidates {
            if let Some(label) = client_map
                .get(port)
                .and_then(|labels| labels.get(transport))
            {
                return Some(label);
            }
        }

        None
    }
}

/// Discovered port information for a PID.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PortInfo {
    pub pid: u32,
    pub client_type: ClientType,
    pub ports: Vec<(u16, PortLabel)>,
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
            (9000, PortLabel::ClDiscovery),
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
            (9000, PortLabel::ClDiscovery),
        ],
        ClientType::Lodestar => &[
            (9596, PortLabel::ClBeaconApi),
            (9000, PortLabel::ClP2PTcp),
            (9000, PortLabel::ClDiscovery),
        ],
        ClientType::Nimbus => &[
            (5052, PortLabel::ClBeaconApi),
            (9000, PortLabel::ClP2PTcp),
            (9000, PortLabel::ClDiscovery),
        ],
        ClientType::Grandine => &[
            (5052, PortLabel::ClBeaconApi),
            (9000, PortLabel::ClP2PTcp),
            (9000, PortLabel::ClDiscovery),
        ],
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
        ClientType::Grandine => &[
            ("--http-port", PortLabel::ClBeaconApi),
            ("--libp2p-port", PortLabel::ClP2PTcp),
            ("--discovery-port", PortLabel::ClDiscovery),
            ("--enr-tcp-port", PortLabel::ClP2PTcp),
            ("--enr-udp-port", PortLabel::ClDiscovery),
            ("--libp2p-port-ipv6", PortLabel::ClP2PTcp),
            ("--discovery-port-ipv6", PortLabel::ClDiscovery),
            ("--enr-tcp-port-ipv6", PortLabel::ClP2PTcp),
            ("--enr-udp-port-ipv6", PortLabel::ClDiscovery),
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

        let mut ports = Vec::with_capacity(8);

        // Try to parse ports from cmdline.
        match read_proc_cmdline(pid) {
            Ok(cmdline) => {
                let parsed = parse_ports_from_cmdline(&cmdline, client_type);
                for (port, label) in parsed {
                    upsert_port_label(&mut ports, port, label);
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
                upsert_port_label(&mut ports, port, label);
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

/// Collect all client-aware port mappings across all PIDs.
pub fn all_port_labels(port_infos: &HashMap<u32, PortInfo>) -> PortLabelMap {
    let mut result = PortLabelMap::default();

    let mut pids: Vec<u32> = port_infos.keys().copied().collect();
    pids.sort_unstable();

    for pid in pids {
        if let Some(info) = port_infos.get(&pid) {
            for &(port, label) in &info.ports {
                result.insert(info.client_type, port, label);
            }
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

    fn assert_contains_label(ports: &[(u16, PortLabel)], port: u16, label: PortLabel) {
        assert!(
            ports
                .iter()
                .any(|(candidate_port, candidate_label)| *candidate_port == port
                    && *candidate_label == label),
            "missing {label:?} for port {port}",
        );
    }

    #[test]
    fn test_port_label_as_str() {
        assert_eq!(PortLabel::Unknown.as_str(), "unknown");
        assert_eq!(PortLabel::ElP2PTcp.as_str(), "el_p2p");
        assert_eq!(PortLabel::ElJsonRpc.as_str(), "el_json_rpc");
        assert_eq!(PortLabel::ClP2PTcp.as_str(), "cl_p2p");
        assert_eq!(PortLabel::ClP2PQuic.as_str(), "cl_p2p");
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
    fn test_port_label_transport() {
        assert_eq!(PortLabel::ElP2PTcp.transport(), PortTransport::Tcp);
        assert_eq!(PortLabel::ElDiscovery.transport(), PortTransport::Udp);
        assert_eq!(PortLabel::ClP2PQuic.transport(), PortTransport::Udp);
        assert_eq!(PortLabel::Unknown.transport(), PortTransport::Any);
    }

    #[test]
    fn test_default_ports_geth() {
        let ports = default_ports(ClientType::Geth);
        assert_contains_label(ports, 8545, PortLabel::ElJsonRpc);
        assert_contains_label(ports, 8546, PortLabel::ElWebSocket);
        assert_contains_label(ports, 8551, PortLabel::ElEngineApi);
        assert_contains_label(ports, 30303, PortLabel::ElP2PTcp);
        assert_eq!(ports.len(), 4);
    }

    #[test]
    fn test_default_ports_lighthouse() {
        let ports = default_ports(ClientType::Lighthouse);
        assert_contains_label(ports, 5052, PortLabel::ClBeaconApi);
        assert_contains_label(ports, 9000, PortLabel::ClP2PTcp);
        assert_contains_label(ports, 9000, PortLabel::ClDiscovery);
        assert_contains_label(ports, 9001, PortLabel::ClP2PQuic);
    }

    #[test]
    fn test_default_ports_prysm() {
        let ports = default_ports(ClientType::Prysm);
        assert_contains_label(ports, 3500, PortLabel::ClBeaconApi);
        assert_contains_label(ports, 4000, PortLabel::ClGrpc);
        assert_contains_label(ports, 13000, PortLabel::ClP2PTcp);
        assert_contains_label(ports, 12000, PortLabel::ClDiscovery);
    }

    #[test]
    fn test_default_ports_grandine() {
        let ports = default_ports(ClientType::Grandine);
        assert_contains_label(ports, 5052, PortLabel::ClBeaconApi);
        assert_contains_label(ports, 9000, PortLabel::ClP2PTcp);
        assert_contains_label(ports, 9000, PortLabel::ClDiscovery);
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
        let cmdline =
            "beacon-chain --grpc-gateway-port 3500 --rpc-port 4000 --p2p-tcp-port 13000 --p2p-udp-port 13000";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Prysm);
        assert_eq!(
            ports,
            vec![
                (3500, PortLabel::ClBeaconApi),
                (4000, PortLabel::ClGrpc),
                (13000, PortLabel::ClP2PTcp),
                (13000, PortLabel::ClDiscovery),
            ]
        );
    }

    #[test]
    fn test_parse_ports_grandine() {
        let cmdline =
            "grandine --http-port=5052 --libp2p-port=9000 --discovery-port=9000 --enr-tcp-port=9000 --enr-udp-port=9000";
        let ports = parse_ports_from_cmdline(cmdline, ClientType::Grandine);
        assert_contains_label(&ports, 5052, PortLabel::ClBeaconApi);
        assert_contains_label(&ports, 9000, PortLabel::ClP2PTcp);
        assert_contains_label(&ports, 9000, PortLabel::ClDiscovery);
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
    fn test_all_port_labels_protocol_and_client_aware() {
        let mut infos = HashMap::new();
        infos.insert(
            1,
            PortInfo {
                pid: 1,
                client_type: ClientType::Prysm,
                ports: vec![
                    (3500, PortLabel::ClBeaconApi),
                    (13000, PortLabel::ClP2PTcp),
                    (13000, PortLabel::ClDiscovery),
                ],
            },
        );

        infos.insert(
            2,
            PortInfo {
                pid: 2,
                client_type: ClientType::Geth,
                ports: vec![
                    (30303, PortLabel::ElP2PTcp),
                    (30303, PortLabel::ElDiscovery),
                ],
            },
        );

        let all = all_port_labels(&infos);

        assert_eq!(
            all.resolve_tcp(ClientType::Prysm, 13000, 0),
            PortLabel::ClP2PTcp
        );
        assert_eq!(
            all.resolve_udp(ClientType::Prysm, 13000, 0),
            PortLabel::ClDiscovery
        );

        assert_eq!(
            all.resolve_tcp(ClientType::Geth, 30303, 0),
            PortLabel::ElP2PTcp
        );
        assert_eq!(
            all.resolve_udp(ClientType::Geth, 30303, 0),
            PortLabel::ElDiscovery
        );

        // Client-specific lookups do not bleed across client types.
        assert_eq!(
            all.resolve_tcp(ClientType::Lighthouse, 13000, 0),
            PortLabel::Unknown
        );
    }

    #[test]
    fn test_port_label_map_prefers_primary_then_secondary_port() {
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);

        assert_eq!(
            map.resolve_tcp(ClientType::Prysm, 13000, 45000),
            PortLabel::ClP2PTcp
        );
        assert_eq!(
            map.resolve_tcp(ClientType::Prysm, 45000, 13000),
            PortLabel::ClP2PTcp
        );
        assert_eq!(
            map.resolve_tcp(ClientType::Prysm, 45000, 45001),
            PortLabel::Unknown
        );
    }

    #[test]
    fn test_upsert_port_label_preserves_tcp_udp_pair() {
        let mut ports = Vec::new();
        upsert_port_label(&mut ports, 9000, PortLabel::ClP2PTcp);
        upsert_port_label(&mut ports, 9000, PortLabel::ClDiscovery);

        assert_eq!(ports.len(), 2);
        assert_contains_label(&ports, 9000, PortLabel::ClP2PTcp);
        assert_contains_label(&ports, 9000, PortLabel::ClDiscovery);
    }
}
