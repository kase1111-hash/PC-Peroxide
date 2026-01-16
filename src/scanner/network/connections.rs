//! Network connection enumeration.
//!
//! Provides cross-platform network connection listing:
//! - Windows: Uses netstat parsing or GetTcpTable2/GetUdpTable
//! - Linux: Reads /proc/net/tcp and /proc/net/udp
//! - macOS: Uses netstat parsing

use crate::core::error::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::ports::PortInfo;

/// Type of network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionType {
    /// TCP connection
    Tcp,
    /// UDP socket
    Udp,
    /// TCP6 (IPv6)
    Tcp6,
    /// UDP6 (IPv6)
    Udp6,
}

impl std::fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Tcp6 => write!(f, "TCP6"),
            Self::Udp6 => write!(f, "UDP6"),
        }
    }
}

/// State of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionState {
    /// Socket is listening for connections
    Listen,
    /// Connection established
    Established,
    /// Sent SYN, waiting for SYN-ACK
    SynSent,
    /// Received SYN, sent SYN-ACK
    SynReceived,
    /// FIN sent, waiting for ACK
    FinWait1,
    /// Received ACK for FIN
    FinWait2,
    /// Waiting for remote FIN
    CloseWait,
    /// FIN sent after receiving FIN
    Closing,
    /// Waiting for FIN ACK
    LastAck,
    /// Waiting for enough time to pass
    TimeWait,
    /// Connection closed
    Closed,
    /// Unknown state
    Unknown,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Listen => write!(f, "LISTEN"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynReceived => write!(f, "SYN_RECV"),
            Self::FinWait1 => write!(f, "FIN_WAIT1"),
            Self::FinWait2 => write!(f, "FIN_WAIT2"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::Closing => write!(f, "CLOSING"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::Closed => write!(f, "CLOSED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Represents a network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Connection type (TCP/UDP)
    pub conn_type: ConnectionType,
    /// Local IP address
    pub local_addr: IpAddr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address (if connected)
    pub remote_addr: Option<IpAddr>,
    /// Remote port (if connected)
    pub remote_port: Option<u16>,
    /// Connection state
    pub state: ConnectionState,
    /// Process ID owning this connection
    pub pid: Option<u32>,
    /// Process name (if available)
    pub process_name: Option<String>,
}

impl Connection {
    /// Check if this is a loopback connection.
    pub fn is_loopback(&self) -> bool {
        self.local_addr.is_loopback()
            || self.remote_addr.map_or(false, |a| a.is_loopback())
    }

    /// Check if this is a listening socket.
    pub fn is_listening(&self) -> bool {
        self.state == ConnectionState::Listen
    }

    /// Check if this is an established connection.
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }
}

/// Result of scanning a network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanResult {
    /// The connection
    pub connection: Connection,
    /// Local port analysis
    pub local_port_info: PortInfo,
    /// Remote port analysis (if connected)
    pub remote_port_info: Option<PortInfo>,
    /// Whether this connection is suspicious
    pub suspicious: bool,
    /// Severity score (0-100)
    pub severity: u8,
}

/// Network connection scanner.
pub struct ConnectionScanner {
    /// Include loopback connections
    include_loopback: bool,
}

impl ConnectionScanner {
    /// Create a new connection scanner.
    pub fn new() -> Self {
        Self {
            include_loopback: false,
        }
    }

    /// Configure whether to include loopback connections.
    pub fn with_loopback(mut self, include: bool) -> Self {
        self.include_loopback = include;
        self
    }

    /// Enumerate all network connections.
    pub fn enumerate_connections(&self) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();

        #[cfg(target_os = "linux")]
        {
            connections.extend(self.parse_proc_net_tcp("/proc/net/tcp", ConnectionType::Tcp)?);
            connections.extend(self.parse_proc_net_tcp("/proc/net/tcp6", ConnectionType::Tcp6)?);
            connections.extend(self.parse_proc_net_udp("/proc/net/udp", ConnectionType::Udp)?);
            connections.extend(self.parse_proc_net_udp("/proc/net/udp6", ConnectionType::Udp6)?);
        }

        #[cfg(target_os = "windows")]
        {
            connections.extend(self.parse_netstat_windows()?);
        }

        #[cfg(target_os = "macos")]
        {
            connections.extend(self.parse_netstat_macos()?);
        }

        // Filter loopback if not included
        if !self.include_loopback {
            connections.retain(|c| !c.is_loopback());
        }

        Ok(connections)
    }

    /// Parse Linux /proc/net/tcp format.
    #[cfg(target_os = "linux")]
    fn parse_proc_net_tcp(&self, path: &str, conn_type: ConnectionType) -> Result<Vec<Connection>> {
        use std::fs;
        

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(Vec::new()),
        };

        let mut connections = Vec::new();

        for line in content.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            // Parse local address
            let local_parts: Vec<&str> = parts[1].split(':').collect();
            if local_parts.len() != 2 {
                continue;
            }

            let local_addr = Self::parse_hex_ip(local_parts[0], &conn_type);
            let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);

            // Parse remote address
            let remote_parts: Vec<&str> = parts[2].split(':').collect();
            let (remote_addr, remote_port) = if remote_parts.len() == 2 {
                let addr = Self::parse_hex_ip(remote_parts[0], &conn_type);
                let port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);
                if port == 0 && Self::is_zero_ip(&addr) {
                    (None, None)
                } else {
                    (Some(addr), Some(port))
                }
            } else {
                (None, None)
            };

            // Parse state
            let state_num = u8::from_str_radix(parts[3], 16).unwrap_or(0);
            let state = Self::tcp_state_from_num(state_num);

            // Parse UID and inode for PID lookup
            let inode: u64 = parts[9].parse().unwrap_or(0);
            let pid = self.find_pid_by_inode(inode);

            connections.push(Connection {
                conn_type,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid,
                process_name: pid.and_then(|p| self.get_process_name(p)),
            });
        }

        Ok(connections)
    }

    /// Parse Linux /proc/net/udp format.
    #[cfg(target_os = "linux")]
    fn parse_proc_net_udp(&self, path: &str, conn_type: ConnectionType) -> Result<Vec<Connection>> {
        use std::fs;

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(Vec::new()),
        };

        let mut connections = Vec::new();

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let local_parts: Vec<&str> = parts[1].split(':').collect();
            if local_parts.len() != 2 {
                continue;
            }

            let local_addr = Self::parse_hex_ip(local_parts[0], &conn_type);
            let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);

            let remote_parts: Vec<&str> = parts[2].split(':').collect();
            let (remote_addr, remote_port) = if remote_parts.len() == 2 {
                let addr = Self::parse_hex_ip(remote_parts[0], &conn_type);
                let port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);
                if port == 0 && Self::is_zero_ip(&addr) {
                    (None, None)
                } else {
                    (Some(addr), Some(port))
                }
            } else {
                (None, None)
            };

            let inode: u64 = parts[9].parse().unwrap_or(0);
            let pid = self.find_pid_by_inode(inode);

            // UDP doesn't have states like TCP
            connections.push(Connection {
                conn_type,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state: ConnectionState::Unknown,
                pid,
                process_name: pid.and_then(|p| self.get_process_name(p)),
            });
        }

        Ok(connections)
    }

    /// Parse hex IP address from /proc/net format.
    #[cfg(target_os = "linux")]
    fn parse_hex_ip(hex: &str, conn_type: &ConnectionType) -> IpAddr {
        use std::net::{Ipv4Addr, Ipv6Addr};

        match conn_type {
            ConnectionType::Tcp | ConnectionType::Udp => {
                // IPv4: little-endian hex
                let value = u32::from_str_radix(hex, 16).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(value.swap_bytes()))
            }
            ConnectionType::Tcp6 | ConnectionType::Udp6 => {
                // IPv6: 32 hex chars, need to handle byte order
                if hex.len() != 32 {
                    return IpAddr::V6(Ipv6Addr::UNSPECIFIED);
                }
                let mut bytes = [0u8; 16];
                for i in 0..16 {
                    // Linux stores IPv6 in 4-byte groups, each little-endian
                    let group = i / 4;
                    let offset = 3 - (i % 4);
                    let idx = group * 8 + offset * 2;
                    bytes[i] = u8::from_str_radix(&hex[idx..idx + 2], 16).unwrap_or(0);
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
        }
    }

    /// Check if an IP is all zeros.
    #[cfg(target_os = "linux")]
    fn is_zero_ip(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }

    /// Convert TCP state number to enum.
    #[cfg(target_os = "linux")]
    fn tcp_state_from_num(num: u8) -> ConnectionState {
        match num {
            1 => ConnectionState::Established,
            2 => ConnectionState::SynSent,
            3 => ConnectionState::SynReceived,
            4 => ConnectionState::FinWait1,
            5 => ConnectionState::FinWait2,
            6 => ConnectionState::TimeWait,
            7 => ConnectionState::Closed,
            8 => ConnectionState::CloseWait,
            9 => ConnectionState::LastAck,
            10 => ConnectionState::Listen,
            11 => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }

    /// Find process ID by socket inode.
    #[cfg(target_os = "linux")]
    fn find_pid_by_inode(&self, inode: u64) -> Option<u32> {
        use std::fs;
        

        if inode == 0 {
            return None;
        }

        let socket_link = format!("socket:[{}]", inode);

        // Iterate through /proc/*/fd/*
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return None,
        };

        for entry in proc_dir.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let pid_str = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) => s,
                None => continue,
            };

            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_path = path.join("fd");
            let fd_dir = match fs::read_dir(&fd_path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            for fd_entry in fd_dir.filter_map(|e| e.ok()) {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    if link.to_string_lossy() == socket_link {
                        return Some(pid);
                    }
                }
            }
        }

        None
    }

    /// Get process name from PID.
    #[cfg(target_os = "linux")]
    fn get_process_name(&self, pid: u32) -> Option<String> {
        use std::fs;

        fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    /// Parse netstat output on Windows.
    #[cfg(target_os = "windows")]
    fn parse_netstat_windows(&self) -> Result<Vec<Connection>> {
        use std::process::Command;

        let output = Command::new("netstat")
            .args(["-ano"])
            .output()
            .map_err(|e| Error::Internal(format!("Failed to run netstat: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut connections = Vec::new();

        for line in stdout.lines().skip(4) {
            // Skip header lines
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let proto = parts[0].to_uppercase();
            let conn_type = match proto.as_str() {
                "TCP" => ConnectionType::Tcp,
                "UDP" => ConnectionType::Udp,
                _ => continue,
            };

            // Parse local address
            let local_parts: Vec<&str> = parts[1].rsplitn(2, ':').collect();
            if local_parts.len() != 2 {
                continue;
            }
            let local_port: u16 = local_parts[0].parse().unwrap_or(0);
            let local_addr: IpAddr = local_parts[1]
                .replace("[", "")
                .replace("]", "")
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

            // Parse remote address and state
            let (remote_addr, remote_port, state, pid_idx) = if conn_type == ConnectionType::Tcp {
                let remote_parts: Vec<&str> = parts[2].rsplitn(2, ':').collect();
                let (ra, rp) = if remote_parts.len() == 2 {
                    let addr: IpAddr = remote_parts[1]
                        .replace("[", "")
                        .replace("]", "")
                        .parse()
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                    let port: u16 = remote_parts[0].parse().unwrap_or(0);
                    if port == 0 {
                        (None, None)
                    } else {
                        (Some(addr), Some(port))
                    }
                } else {
                    (None, None)
                };

                let state = match parts.get(3).map(|s| s.to_uppercase()).as_deref() {
                    Some("LISTENING") => ConnectionState::Listen,
                    Some("ESTABLISHED") => ConnectionState::Established,
                    Some("SYN_SENT") => ConnectionState::SynSent,
                    Some("SYN_RECEIVED") => ConnectionState::SynReceived,
                    Some("FIN_WAIT_1") => ConnectionState::FinWait1,
                    Some("FIN_WAIT_2") => ConnectionState::FinWait2,
                    Some("CLOSE_WAIT") => ConnectionState::CloseWait,
                    Some("CLOSING") => ConnectionState::Closing,
                    Some("LAST_ACK") => ConnectionState::LastAck,
                    Some("TIME_WAIT") => ConnectionState::TimeWait,
                    Some("CLOSED") => ConnectionState::Closed,
                    _ => ConnectionState::Unknown,
                };

                (ra, rp, state, 4)
            } else {
                // UDP doesn't have state or remote in listening mode
                (None, None, ConnectionState::Unknown, 3)
            };

            let pid: Option<u32> = parts.get(pid_idx).and_then(|s| s.parse().ok());

            connections.push(Connection {
                conn_type,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid,
                process_name: None, // Would need additional lookup
            });
        }

        Ok(connections)
    }

    /// Parse netstat output on macOS.
    #[cfg(target_os = "macos")]
    fn parse_netstat_macos(&self) -> Result<Vec<Connection>> {
        use std::process::Command;

        let output = Command::new("netstat")
            .args(["-anv", "-p", "tcp"])
            .output()
            .map_err(|e| Error::Internal(format!("Failed to run netstat: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut connections = Vec::new();

        for line in stdout.lines() {
            if !line.starts_with("tcp") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            // Parse local address (format: addr.port or addr:port)
            let local = parts[3];
            let (local_addr, local_port) = Self::parse_macos_address(local);

            // Parse remote address
            let remote = parts[4];
            let (remote_addr, remote_port) = Self::parse_macos_address(remote);
            let remote_addr = if remote_port == Some(0) { None } else { remote_addr };
            let remote_port = if remote_port == Some(0) { None } else { remote_port };

            // Parse state
            let state = match parts.get(5).map(|s| s.to_uppercase()).as_deref() {
                Some("LISTEN") => ConnectionState::Listen,
                Some("ESTABLISHED") => ConnectionState::Established,
                Some("SYN_SENT") => ConnectionState::SynSent,
                Some("SYN_RECEIVED") => ConnectionState::SynReceived,
                Some("FIN_WAIT_1") => ConnectionState::FinWait1,
                Some("FIN_WAIT_2") => ConnectionState::FinWait2,
                Some("CLOSE_WAIT") => ConnectionState::CloseWait,
                Some("CLOSING") => ConnectionState::Closing,
                Some("LAST_ACK") => ConnectionState::LastAck,
                Some("TIME_WAIT") => ConnectionState::TimeWait,
                Some("CLOSED") => ConnectionState::Closed,
                _ => ConnectionState::Unknown,
            };

            if let Some(addr) = local_addr {
                connections.push(Connection {
                    conn_type: ConnectionType::Tcp,
                    local_addr: addr,
                    local_port: local_port.unwrap_or(0),
                    remote_addr,
                    remote_port,
                    state,
                    pid: None,
                    process_name: None,
                });
            }
        }

        Ok(connections)
    }

    /// Parse macOS netstat address format (addr.port).
    #[cfg(target_os = "macos")]
    fn parse_macos_address(addr_str: &str) -> (Option<IpAddr>, Option<u16>) {
        // Format can be "*.port" for listening or "addr.port"
        if addr_str.starts_with("*.") {
            let port: u16 = addr_str[2..].parse().unwrap_or(0);
            return (Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)), Some(port));
        }

        // Find last dot for port
        if let Some(last_dot) = addr_str.rfind('.') {
            let addr_part = &addr_str[..last_dot];
            let port_part = &addr_str[last_dot + 1..];

            let port: u16 = port_part.parse().unwrap_or(0);
            let addr: IpAddr = addr_part.parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

            (Some(addr), Some(port))
        } else {
            (None, None)
        }
    }
}

impl Default for ConnectionScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_type_display() {
        assert_eq!(format!("{}", ConnectionType::Tcp), "TCP");
        assert_eq!(format!("{}", ConnectionType::Udp), "UDP");
        assert_eq!(format!("{}", ConnectionType::Tcp6), "TCP6");
        assert_eq!(format!("{}", ConnectionType::Udp6), "UDP6");
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(format!("{}", ConnectionState::Listen), "LISTEN");
        assert_eq!(format!("{}", ConnectionState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", ConnectionState::TimeWait), "TIME_WAIT");
    }

    #[test]
    fn test_connection_is_loopback() {
        let conn = Connection {
            conn_type: ConnectionType::Tcp,
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 8080,
            remote_addr: None,
            remote_port: None,
            state: ConnectionState::Listen,
            pid: None,
            process_name: None,
        };
        assert!(conn.is_loopback());

        let conn2 = Connection {
            conn_type: ConnectionType::Tcp,
            local_addr: "192.168.1.1".parse().unwrap(),
            local_port: 8080,
            remote_addr: None,
            remote_port: None,
            state: ConnectionState::Listen,
            pid: None,
            process_name: None,
        };
        assert!(!conn2.is_loopback());
    }

    #[test]
    fn test_connection_scanner_creation() {
        let scanner = ConnectionScanner::new();
        assert!(!scanner.include_loopback);
    }

    #[test]
    fn test_enumerate_connections() {
        let scanner = ConnectionScanner::new();
        // Should not panic
        let _ = scanner.enumerate_connections();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_hex_ip_v4() {
        let ip = ConnectionScanner::parse_hex_ip("0100007F", &ConnectionType::Tcp);
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tcp_state_mapping() {
        assert_eq!(ConnectionScanner::tcp_state_from_num(1), ConnectionState::Established);
        assert_eq!(ConnectionScanner::tcp_state_from_num(10), ConnectionState::Listen);
        assert_eq!(ConnectionScanner::tcp_state_from_num(99), ConnectionState::Unknown);
    }
}
