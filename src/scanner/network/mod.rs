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
    include_listening: bool,
    include_established: bool,
}

impl NetworkScanner {
    /// Create a new network scanner with default settings.
    pub fn new() -> Self {
        Self {
            connection_scanner: ConnectionScanner::new(),
            port_detector: SuspiciousPortDetector::new(),
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

            let suspicious = port_info.suspicious
                || remote_port_info.as_ref().is_some_and(|p| p.suspicious);

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

    /// Check if an IP address is in a known blocklist.
    pub fn is_ip_suspicious(&self, _ip: &IpAddr) -> bool {
        // TODO: Implement IP reputation checking
        // For now, check for known suspicious patterns
        false
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
}
