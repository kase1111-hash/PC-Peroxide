//! Network connection scanner for detecting suspicious network activity.
//!
//! This module provides:
//! - Active connection enumeration
//! - Suspicious port detection
//! - Known malware C2 port identification
//! - Connection-to-process mapping

pub mod connections;
pub mod ports;

pub use connections::{
    Connection, ConnectionScanner, ConnectionState, ConnectionType, NetworkScanResult,
};
pub use ports::{PortCategory, PortInfo, SuspiciousPortDetector};

use crate::core::error::Result;
use std::net::IpAddr;

/// Network scanner combining connection enumeration and suspicious port detection.
pub struct NetworkScanner {
    connection_scanner: ConnectionScanner,
    port_detector: SuspiciousPortDetector,
    ip_reputation: IpReputationChecker,
    include_listening: bool,
    include_established: bool,
}

/// IP reputation checker for identifying suspicious IP addresses.
pub struct IpReputationChecker {
    /// Known malicious IP ranges (simplified for now)
    suspicious_ranges: Vec<SuspiciousIpRange>,
}

/// A suspicious IP range with metadata.
struct SuspiciousIpRange {
    /// Description of why this range is suspicious
    description: &'static str,
    /// Check function
    check: fn(&IpAddr) -> bool,
    /// Severity score (0-100)
    severity: u8,
}

impl Default for IpReputationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl IpReputationChecker {
    /// Create a new IP reputation checker with default rules.
    pub fn new() -> Self {
        Self {
            suspicious_ranges: vec![
                // Localhost/loopback connections to unusual ports are generally fine
                // Private ranges connecting externally could be suspicious in some contexts

                // Known Tor exit node patterns (simplified - in production, use a Tor exit list)
                SuspiciousIpRange {
                    description: "Reserved/bogon address space",
                    check: Self::is_bogon,
                    severity: 30,
                },
                // Unassigned/reserved ranges that shouldn't appear in normal traffic
                SuspiciousIpRange {
                    description: "Documentation range (should not appear in real traffic)",
                    check: Self::is_documentation_range,
                    severity: 50,
                },
            ],
        }
    }

    /// Check if an IP is suspicious and return details.
    pub fn check(&self, ip: &IpAddr) -> Option<IpReputationResult> {
        for range in &self.suspicious_ranges {
            if (range.check)(ip) {
                return Some(IpReputationResult {
                    suspicious: true,
                    description: range.description.to_string(),
                    severity: range.severity,
                });
            }
        }
        None
    }

    /// Check if IP is in bogon (unallocated/reserved) space.
    fn is_bogon(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 0.0.0.0/8 - "This" network
                octets[0] == 0
                // 240.0.0.0/4 - Reserved for future use (mostly)
                || octets[0] >= 240
            }
            IpAddr::V6(ipv6) => {
                // Check for deprecated/reserved IPv6 ranges
                let segments = ipv6.segments();
                // Deprecated site-local (fec0::/10)
                segments[0] & 0xffc0 == 0xfec0
            }
        }
    }

    /// Check if IP is in documentation range (should not appear in real traffic).
    fn is_documentation_range(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 192.0.2.0/24 - TEST-NET-1 (documentation)
                (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                // 198.51.100.0/24 - TEST-NET-2 (documentation)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                // 203.0.113.0/24 - TEST-NET-3 (documentation)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                // 2001:db8::/32 - Documentation range
                segments[0] == 0x2001 && segments[1] == 0x0db8
            }
        }
    }
}

/// Result of IP reputation check.
#[derive(Debug, Clone)]
pub struct IpReputationResult {
    /// Whether the IP is considered suspicious
    pub suspicious: bool,
    /// Description of why
    pub description: String,
    /// Severity score
    pub severity: u8,
}

impl NetworkScanner {
    /// Create a new network scanner with default settings.
    pub fn new() -> Self {
        Self {
            connection_scanner: ConnectionScanner::new(),
            port_detector: SuspiciousPortDetector::new(),
            ip_reputation: IpReputationChecker::new(),
            include_listening: true,
            include_established: true,
        }
    }

    /// Configure whether to include listening sockets.
    pub fn with_listening(mut self, include: bool) -> Self {
        self.include_listening = include;
        self
    }

    /// Configure whether to include established connections.
    pub fn with_established(mut self, include: bool) -> Self {
        self.include_established = include;
        self
    }

    /// Scan all network connections and identify suspicious ones.
    pub fn scan_all(&self) -> Result<Vec<NetworkScanResult>> {
        let connections = self.connection_scanner.enumerate_connections()?;

        let mut results = Vec::new();
        for conn in connections {
            // Filter by state
            if !self.include_listening && conn.state == ConnectionState::Listen {
                continue;
            }
            if !self.include_established && conn.state == ConnectionState::Established {
                continue;
            }

            let port_info = self.port_detector.analyze_port(conn.local_port);
            let remote_port_info = conn.remote_port.map(|p| self.port_detector.analyze_port(p));

            let suspicious =
                port_info.suspicious || remote_port_info.as_ref().is_some_and(|p| p.suspicious);

            let severity = std::cmp::max(
                port_info.severity,
                remote_port_info.as_ref().map_or(0, |p| p.severity),
            );

            results.push(NetworkScanResult {
                connection: conn,
                local_port_info: port_info,
                remote_port_info,
                suspicious,
                severity,
            });
        }

        Ok(results)
    }

    /// Scan only suspicious network connections.
    pub fn scan_suspicious(&self) -> Result<Vec<NetworkScanResult>> {
        let all = self.scan_all()?;
        Ok(all.into_iter().filter(|r| r.suspicious).collect())
    }

    /// Get connections for a specific process ID.
    pub fn scan_pid(&self, pid: u32) -> Result<Vec<NetworkScanResult>> {
        let all = self.scan_all()?;
        Ok(all
            .into_iter()
            .filter(|r| r.connection.pid == Some(pid))
            .collect())
    }

    /// Check if an IP address is in a known blocklist or suspicious range.
    pub fn is_ip_suspicious(&self, ip: &IpAddr) -> bool {
        self.ip_reputation.check(ip).is_some()
    }

    /// Get detailed IP reputation information.
    pub fn get_ip_reputation(&self, ip: &IpAddr) -> Option<IpReputationResult> {
        self.ip_reputation.check(ip)
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_network_scanner_creation() {
        let scanner = NetworkScanner::new();
        assert!(scanner.include_listening);
        assert!(scanner.include_established);
    }

    #[test]
    fn test_network_scanner_config() {
        let scanner = NetworkScanner::new()
            .with_listening(false)
            .with_established(true);
        assert!(!scanner.include_listening);
        assert!(scanner.include_established);
    }

    #[test]
    fn test_scan_all() {
        let scanner = NetworkScanner::new();
        // Should not panic
        let _ = scanner.scan_all();
    }

    #[test]
    fn test_ip_reputation_normal_ip() {
        let checker = IpReputationChecker::new();
        // Normal public IP should not be suspicious
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(checker.check(&ip).is_none());
    }

    #[test]
    fn test_ip_reputation_bogon() {
        let checker = IpReputationChecker::new();
        // 0.0.0.0/8 should be flagged as bogon
        let ip = IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3));
        let result = checker.check(&ip);
        assert!(result.is_some());
        assert!(result.unwrap().description.contains("bogon"));
    }

    #[test]
    fn test_ip_reputation_documentation_range() {
        let checker = IpReputationChecker::new();
        // 192.0.2.0/24 (TEST-NET-1) should be flagged
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let result = checker.check(&ip);
        assert!(result.is_some());
        assert!(result.unwrap().description.contains("Documentation"));
    }

    #[test]
    fn test_ip_reputation_documentation_range_v6() {
        let checker = IpReputationChecker::new();
        // 2001:db8::/32 should be flagged
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let result = checker.check(&ip);
        assert!(result.is_some());
    }

    #[test]
    fn test_scanner_is_ip_suspicious() {
        let scanner = NetworkScanner::new();
        // Normal IP
        assert!(!scanner.is_ip_suspicious(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // Bogon IP
        assert!(scanner.is_ip_suspicious(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))));
    }
}
