use crate::agent::ports::PortLabel;

/// Dimension key for metrics that only need PID + client type.
/// Used for syscalls, page faults, scheduler events, memory events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BasicDimension {
    pub pid: u32,
    pub client_type: u8,
}

/// Dimension key for per-core scheduler utilization accumulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpuCoreDimension {
    pub pid: u32,
    pub client_type: u8,
    pub cpu_id: u32,
}

/// Dimension key for network I/O metrics.
/// Includes port label and direction for detailed network breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkDimension {
    pub pid: u32,
    pub client_type: u8,
    pub port_label: u8,
    /// 0 = TX, 1 = RX.
    pub direction: u8,
}

/// Dimension key for TCP metrics (RTT, CWND).
/// Similar to network but without direction since these are connection-level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TCPMetricsDimension {
    pub pid: u32,
    pub client_type: u8,
    pub port_label: u8,
}

/// Dimension key for disk I/O metrics.
/// Includes device ID and read/write for per-device breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiskDimension {
    pub pid: u32,
    pub client_type: u8,
    pub device_id: u32,
    /// 0 = read, 1 = write.
    pub rw: u8,
}

/// Returns a human-readable direction string.
pub fn direction_string(dir: u8) -> &'static str {
    if dir == 0 {
        "tx"
    } else {
        "rx"
    }
}

/// Returns a human-readable read/write string.
pub fn rw_string(rw: u8) -> &'static str {
    if rw == 0 {
        "read"
    } else {
        "write"
    }
}

/// Returns a port label string from a u8 discriminant.
pub fn port_label_string(v: u8) -> &'static str {
    PortLabel::from_u8(v).unwrap_or(PortLabel::Unknown).as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_basic_dimension_as_map_key() {
        let mut map: HashMap<BasicDimension, u32> = HashMap::new();
        let dim = BasicDimension {
            pid: 100,
            client_type: 1,
        };
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_basic_dimension_equality() {
        let a = BasicDimension {
            pid: 1,
            client_type: 2,
        };
        let b = BasicDimension {
            pid: 1,
            client_type: 2,
        };
        let c = BasicDimension {
            pid: 1,
            client_type: 3,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_network_dimension_as_map_key() {
        let mut map: HashMap<NetworkDimension, u32> = HashMap::new();
        let dim = NetworkDimension {
            pid: 100,
            client_type: 1,
            port_label: PortLabel::ElJsonRpc as u8,
            direction: 0,
        };
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_cpu_core_dimension_as_map_key() {
        let mut map: HashMap<CpuCoreDimension, u32> = HashMap::new();
        let dim = CpuCoreDimension {
            pid: 100,
            client_type: 1,
            cpu_id: 7,
        };
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_tcp_metrics_dimension_as_map_key() {
        let mut map: HashMap<TCPMetricsDimension, u32> = HashMap::new();
        let dim = TCPMetricsDimension {
            pid: 100,
            client_type: 1,
            port_label: PortLabel::ElP2PTcp as u8,
        };
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_disk_dimension_as_map_key() {
        let mut map: HashMap<DiskDimension, u32> = HashMap::new();
        let dim = DiskDimension {
            pid: 100,
            client_type: 1,
            device_id: 259,
            rw: 0,
        };
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_direction_string() {
        assert_eq!(direction_string(0), "tx");
        assert_eq!(direction_string(1), "rx");
        assert_eq!(direction_string(2), "rx");
    }

    #[test]
    fn test_rw_string() {
        assert_eq!(rw_string(0), "read");
        assert_eq!(rw_string(1), "write");
        assert_eq!(rw_string(2), "write");
    }

    #[test]
    fn test_port_label_string() {
        assert_eq!(port_label_string(0), "unknown");
        assert_eq!(port_label_string(3), "el_json_rpc");
        assert_eq!(port_label_string(9), "cl_beacon_api");
        assert_eq!(port_label_string(255), "unknown");
    }
}
