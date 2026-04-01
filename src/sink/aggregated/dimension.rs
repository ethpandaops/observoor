use crate::agent::ports::PortLabel;

/// Dimension key for metrics that only need PID + client type.
/// Used for syscalls, page faults, scheduler events, memory events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BasicDimension(u64);

/// Dimension key for per-core scheduler utilization accumulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CpuCoreDimension(u128);

/// Dimension key for network I/O metrics.
/// Includes port label and direction for detailed network breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct NetworkDimension(u64);

/// Dimension key for TCP metrics (RTT, CWND).
/// Similar to network but without direction since these are connection-level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TCPMetricsDimension(u64);

/// Dimension key for disk I/O metrics.
/// Includes device ID and read/write for per-device breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DiskDimension(u128);

impl BasicDimension {
    #[inline(always)]
    pub fn new(pid: u32, client_type: u8) -> Self {
        Self(pack_basic(pid, client_type))
    }

    #[inline(always)]
    pub fn pid(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    pub fn client_type(self) -> u8 {
        (self.0 >> 32) as u8
    }
}

impl CpuCoreDimension {
    #[inline(always)]
    pub fn new(pid: u32, client_type: u8, cpu_id: u32) -> Self {
        Self(pack_cpu_core(pid, client_type, cpu_id))
    }

    #[inline(always)]
    pub fn pid(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    pub fn client_type(self) -> u8 {
        (self.0 >> 32) as u8
    }

    #[inline(always)]
    pub fn cpu_id(self) -> u32 {
        (self.0 >> 40) as u32
    }
}

impl NetworkDimension {
    #[inline(always)]
    pub fn new(pid: u32, client_type: u8, port_label: u8, direction: u8) -> Self {
        Self(pack_network(pid, client_type, port_label, direction))
    }

    #[inline(always)]
    pub fn pid(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    pub fn client_type(self) -> u8 {
        (self.0 >> 32) as u8
    }

    #[inline(always)]
    pub fn port_label(self) -> u8 {
        (self.0 >> 40) as u8
    }

    #[inline(always)]
    pub fn direction(self) -> u8 {
        (self.0 >> 48) as u8
    }
}

impl TCPMetricsDimension {
    #[inline(always)]
    pub fn new(pid: u32, client_type: u8, port_label: u8) -> Self {
        Self(pack_tcp_metrics(pid, client_type, port_label))
    }

    #[inline(always)]
    pub fn pid(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    pub fn client_type(self) -> u8 {
        (self.0 >> 32) as u8
    }

    #[inline(always)]
    pub fn port_label(self) -> u8 {
        (self.0 >> 40) as u8
    }
}

impl DiskDimension {
    #[inline(always)]
    pub fn new(pid: u32, client_type: u8, device_id: u32, rw: u8) -> Self {
        Self(pack_disk(pid, client_type, device_id, rw))
    }

    #[inline(always)]
    pub fn pid(self) -> u32 {
        self.0 as u32
    }

    #[inline(always)]
    pub fn client_type(self) -> u8 {
        (self.0 >> 32) as u8
    }

    #[inline(always)]
    pub fn device_id(self) -> u32 {
        (self.0 >> 40) as u32
    }

    #[inline(always)]
    pub fn rw(self) -> u8 {
        (self.0 >> 72) as u8
    }
}

#[inline(always)]
fn pack_basic(pid: u32, client_type: u8) -> u64 {
    (pid as u64) | ((client_type as u64) << 32)
}

#[inline(always)]
fn pack_cpu_core(pid: u32, client_type: u8, cpu_id: u32) -> u128 {
    u128::from(pid) | (u128::from(client_type) << 32) | (u128::from(cpu_id) << 40)
}

#[inline(always)]
fn pack_network(pid: u32, client_type: u8, port_label: u8, direction: u8) -> u64 {
    pack_basic(pid, client_type) | (u64::from(port_label) << 40) | (u64::from(direction) << 48)
}

#[inline(always)]
fn pack_tcp_metrics(pid: u32, client_type: u8, port_label: u8) -> u64 {
    pack_basic(pid, client_type) | (u64::from(port_label) << 40)
}

#[inline(always)]
fn pack_disk(pid: u32, client_type: u8, device_id: u32, rw: u8) -> u128 {
    u128::from(pid)
        | (u128::from(client_type) << 32)
        | (u128::from(device_id) << 40)
        | (u128::from(rw) << 72)
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
        let dim = BasicDimension::new(100, 1);
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_basic_dimension_equality() {
        let a = BasicDimension::new(1, 2);
        let b = BasicDimension::new(1, 2);
        let c = BasicDimension::new(1, 3);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_basic_dimension_accessors() {
        let dim = BasicDimension::new(100, 7);
        assert_eq!(dim.pid(), 100);
        assert_eq!(dim.client_type(), 7);
    }

    #[test]
    fn test_network_dimension_as_map_key() {
        let mut map: HashMap<NetworkDimension, u32> = HashMap::new();
        let dim = NetworkDimension::new(100, 1, PortLabel::ElJsonRpc as u8, 0);
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_network_dimension_accessors() {
        let dim = NetworkDimension::new(100, 1, PortLabel::ElJsonRpc as u8, 1);
        assert_eq!(dim.pid(), 100);
        assert_eq!(dim.client_type(), 1);
        assert_eq!(dim.port_label(), PortLabel::ElJsonRpc as u8);
        assert_eq!(dim.direction(), 1);
    }

    #[test]
    fn test_cpu_core_dimension_as_map_key() {
        let mut map: HashMap<CpuCoreDimension, u32> = HashMap::new();
        let dim = CpuCoreDimension::new(100, 1, 7);
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_cpu_core_dimension_accessors() {
        let dim = CpuCoreDimension::new(100, 1, 7);
        assert_eq!(dim.pid(), 100);
        assert_eq!(dim.client_type(), 1);
        assert_eq!(dim.cpu_id(), 7);
    }

    #[test]
    fn test_tcp_metrics_dimension_as_map_key() {
        let mut map: HashMap<TCPMetricsDimension, u32> = HashMap::new();
        let dim = TCPMetricsDimension::new(100, 1, PortLabel::ElP2PTcp as u8);
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_tcp_metrics_dimension_accessors() {
        let dim = TCPMetricsDimension::new(100, 1, PortLabel::ElP2PTcp as u8);
        assert_eq!(dim.pid(), 100);
        assert_eq!(dim.client_type(), 1);
        assert_eq!(dim.port_label(), PortLabel::ElP2PTcp as u8);
    }

    #[test]
    fn test_disk_dimension_as_map_key() {
        let mut map: HashMap<DiskDimension, u32> = HashMap::new();
        let dim = DiskDimension::new(100, 1, 259, 0);
        map.insert(dim, 42);
        assert_eq!(map.get(&dim), Some(&42));
    }

    #[test]
    fn test_disk_dimension_accessors() {
        let dim = DiskDimension::new(100, 1, 259, 1);
        assert_eq!(dim.pid(), 100);
        assert_eq!(dim.client_type(), 1);
        assert_eq!(dim.device_id(), 259);
        assert_eq!(dim.rw(), 1);
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
