//! Suspicious port detection and categorization.
//!
//! Identifies ports commonly used by:
//! - Malware C2 (Command and Control)
//! - RATs (Remote Access Trojans)
//! - Backdoors
//! - Cryptominers
//! - Other suspicious services

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Category of a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortCategory {
    /// Well-known service (HTTP, SSH, etc.)
    WellKnown,
    /// Known C2 (Command and Control) port
    C2,
    /// Remote Access Trojan port
    Rat,
    /// Backdoor port
    Backdoor,
    /// Cryptocurrency miner port
    Miner,
    /// Data exfiltration port
    Exfiltration,
    /// Botnet communication port
    Botnet,
    /// Proxy/tunnel port
    Proxy,
    /// Unknown/unclassified port
    Unknown,
}

impl std::fmt::Display for PortCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WellKnown => write!(f, "Well-Known"),
            Self::C2 => write!(f, "C2"),
            Self::Rat => write!(f, "RAT"),
            Self::Backdoor => write!(f, "Backdoor"),
            Self::Miner => write!(f, "Miner"),
            Self::Exfiltration => write!(f, "Exfiltration"),
            Self::Botnet => write!(f, "Botnet"),
            Self::Proxy => write!(f, "Proxy"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Information about a port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Port category
    pub category: PortCategory,
    /// Service name if known
    pub service: Option<String>,
    /// Description of potential threat
    pub description: Option<String>,
    /// Whether this port is suspicious
    pub suspicious: bool,
    /// Severity score (0-100)
    pub severity: u8,
}

/// Known port entry.
struct KnownPort {
    service: &'static str,
    category: PortCategory,
    description: &'static str,
    suspicious: bool,
    severity: u8,
}

/// Suspicious port detector.
pub struct SuspiciousPortDetector {
    /// Known ports database
    known_ports: HashMap<u16, KnownPort>,
}

impl SuspiciousPortDetector {
    /// Create a new suspicious port detector.
    pub fn new() -> Self {
        let mut known_ports = HashMap::new();

        // Well-known legitimate services
        Self::add_wellknown(&mut known_ports);

        // C2 and RAT ports
        Self::add_c2_ports(&mut known_ports);

        // Backdoor ports
        Self::add_backdoor_ports(&mut known_ports);

        // Miner ports
        Self::add_miner_ports(&mut known_ports);

        // Proxy and tunnel ports
        Self::add_proxy_ports(&mut known_ports);

        Self { known_ports }
    }

    /// Add well-known legitimate service ports.
    fn add_wellknown(ports: &mut HashMap<u16, KnownPort>) {
        let wellknown = [
            (20, "FTP-Data", "FTP data transfer"),
            (21, "FTP", "FTP control"),
            (22, "SSH", "Secure Shell"),
            (23, "Telnet", "Telnet (unencrypted)"),
            (25, "SMTP", "Simple Mail Transfer"),
            (53, "DNS", "Domain Name System"),
            (67, "DHCP", "DHCP server"),
            (68, "DHCP", "DHCP client"),
            (80, "HTTP", "Hypertext Transfer Protocol"),
            (110, "POP3", "Post Office Protocol"),
            (123, "NTP", "Network Time Protocol"),
            (143, "IMAP", "Internet Message Access Protocol"),
            (161, "SNMP", "Simple Network Management Protocol"),
            (443, "HTTPS", "HTTP Secure"),
            (445, "SMB", "Server Message Block"),
            (465, "SMTPS", "SMTP Secure"),
            (587, "Submission", "SMTP submission"),
            (993, "IMAPS", "IMAP Secure"),
            (995, "POP3S", "POP3 Secure"),
            (3306, "MySQL", "MySQL database"),
            (3389, "RDP", "Remote Desktop Protocol"),
            (5432, "PostgreSQL", "PostgreSQL database"),
            (5900, "VNC", "Virtual Network Computing"),
            (8080, "HTTP-Alt", "HTTP alternate"),
            (8443, "HTTPS-Alt", "HTTPS alternate"),
        ];

        for (port, service, desc) in wellknown {
            ports.insert(
                port,
                KnownPort {
                    service,
                    category: PortCategory::WellKnown,
                    description: desc,
                    suspicious: false,
                    severity: 0,
                },
            );
        }
    }

    /// Add known C2 and RAT ports.
    fn add_c2_ports(ports: &mut HashMap<u16, KnownPort>) {
        let c2_ports = [
            // Cobalt Strike default ports
            (50050, "Cobalt Strike", PortCategory::C2, "Cobalt Strike team server default", 90),
            // Metasploit
            (4444, "Meterpreter", PortCategory::Rat, "Metasploit Meterpreter default", 85),
            (4445, "Meterpreter", PortCategory::Rat, "Metasploit Meterpreter alternate", 85),
            // njRAT
            (5552, "njRAT", PortCategory::Rat, "njRAT default port", 90),
            // DarkComet
            (1604, "DarkComet", PortCategory::Rat, "DarkComet RAT default", 90),
            // Poison Ivy
            (3460, "Poison Ivy", PortCategory::Rat, "Poison Ivy RAT default", 90),
            // BlackShades
            (3333, "BlackShades", PortCategory::Rat, "BlackShades RAT port", 85),
            // Gh0st RAT
            (8000, "Gh0st RAT", PortCategory::Rat, "Gh0st RAT default", 80),
            // Quasar RAT
            (4782, "Quasar RAT", PortCategory::Rat, "Quasar RAT default", 85),
            // AsyncRAT
            (6606, "AsyncRAT", PortCategory::Rat, "AsyncRAT default", 85),
            (7707, "AsyncRAT", PortCategory::Rat, "AsyncRAT alternate", 85),
            (8808, "AsyncRAT", PortCategory::Rat, "AsyncRAT alternate", 85),
            // Emotet
            (8080, "Emotet", PortCategory::C2, "Emotet C2 common (shares with HTTP)", 50),
            (7080, "Emotet", PortCategory::C2, "Emotet C2 common", 75),
            // TrickBot
            (449, "TrickBot", PortCategory::C2, "TrickBot C2 port", 80),
            // Qbot
            (443, "Qbot", PortCategory::C2, "Qbot C2 (shares with HTTPS)", 30),
            (995, "Qbot", PortCategory::C2, "Qbot C2 alternate", 50),
            // Empire
            (443, "Empire", PortCategory::C2, "Empire C2 default (shares with HTTPS)", 30),
            // Covenant
            (80, "Covenant", PortCategory::C2, "Covenant C2 (shares with HTTP)", 25),
            (443, "Covenant", PortCategory::C2, "Covenant C2 (shares with HTTPS)", 25),
        ];

        for (port, service, category, desc, severity) in c2_ports {
            // Don't overwrite well-known ports, but mark them as potentially suspicious
            ports.entry(port).or_insert(KnownPort {
                service,
                category,
                description: desc,
                suspicious: true,
                severity,
            });
        }
    }

    /// Add known backdoor ports.
    fn add_backdoor_ports(ports: &mut HashMap<u16, KnownPort>) {
        let backdoor_ports = [
            (31337, "Back Orifice", "Back Orifice backdoor default", 95),
            (12345, "NetBus", "NetBus backdoor port", 90),
            (12346, "NetBus", "NetBus backdoor alternate", 90),
            (20034, "NetBus Pro", "NetBus Pro default", 90),
            (6667, "IRC", "IRC (often used for botnets)", 60),
            (6666, "IRC", "IRC alternate (often used for botnets)", 60),
            (6697, "IRC-SSL", "IRC over SSL", 50),
            (1080, "SOCKS", "SOCKS proxy (potential tunnel)", 45),
            (1337, "Leet", "Common backdoor port", 80),
            (65535, "High Port", "Highest port number (sometimes used by malware)", 40),
            (54321, "BO2K", "Back Orifice 2000 default", 90),
            (27374, "SubSeven", "SubSeven trojan default", 95),
            (27444, "Trinoo", "Trinoo DDoS daemon", 85),
            (27665, "Trinoo", "Trinoo DDoS master", 85),
            (6969, "GateCrasher", "GateCrasher backdoor", 85),
            (7777, "tini", "Common trojan port", 70),
            (9999, "EquationGroup", "Equation Group implant port", 85),
            (9898, "Dabber", "Dabber worm port", 85),
        ];

        for (port, service, desc, severity) in backdoor_ports {
            ports.entry(port).or_insert(KnownPort {
                service,
                category: PortCategory::Backdoor,
                description: desc,
                suspicious: true,
                severity,
            });
        }
    }

    /// Add cryptocurrency miner ports.
    fn add_miner_ports(ports: &mut HashMap<u16, KnownPort>) {
        let miner_ports = [
            (3333, "Stratum", "Stratum mining protocol", 75),
            (4444, "Stratum", "Stratum mining (shared with Meterpreter)", 75),
            (5555, "Stratum", "Stratum mining alternate", 75),
            (7777, "Stratum", "Stratum mining alternate", 70),
            (8888, "Stratum", "Stratum mining alternate", 70),
            (9999, "Stratum", "Stratum mining alternate", 70),
            (14444, "Stratum", "Stratum mining (Monero common)", 80),
            (45700, "MoneroOcean", "MoneroOcean mining pool", 80),
            (10128, "XMRig", "XMRig miner port", 85),
        ];

        for (port, service, desc, severity) in miner_ports {
            ports.entry(port).or_insert(KnownPort {
                service,
                category: PortCategory::Miner,
                description: desc,
                suspicious: true,
                severity,
            });
        }
    }

    /// Add proxy and tunnel ports.
    fn add_proxy_ports(ports: &mut HashMap<u16, KnownPort>) {
        let proxy_ports = [
            (1080, "SOCKS", "SOCKS proxy", 50),
            (3128, "Squid", "Squid HTTP proxy", 40),
            (8118, "Privoxy", "Privoxy proxy", 45),
            (9050, "Tor", "Tor SOCKS proxy", 60),
            (9051, "Tor", "Tor control port", 65),
            (9150, "Tor Browser", "Tor Browser SOCKS", 55),
            (8123, "Polipo", "Polipo HTTP proxy", 45),
        ];

        for (port, service, desc, severity) in proxy_ports {
            ports.entry(port).or_insert(KnownPort {
                service,
                category: PortCategory::Proxy,
                description: desc,
                suspicious: true,
                severity,
            });
        }
    }

    /// Analyze a port and return information about it.
    pub fn analyze_port(&self, port: u16) -> PortInfo {
        if let Some(known) = self.known_ports.get(&port) {
            PortInfo {
                port,
                category: known.category,
                service: Some(known.service.to_string()),
                description: Some(known.description.to_string()),
                suspicious: known.suspicious,
                severity: known.severity,
            }
        } else {
            // Unknown port - slightly suspicious if in ephemeral range
            let _suspicious = port > 1024 && port < 49152;
            PortInfo {
                port,
                category: PortCategory::Unknown,
                service: None,
                description: None,
                suspicious: false, // Unknown ports aren't inherently suspicious
                severity: 0,
            }
        }
    }

    /// Check if a port is in the known suspicious list.
    pub fn is_suspicious(&self, port: u16) -> bool {
        self.known_ports.get(&port).is_some_and(|p| p.suspicious)
    }

    /// Get all suspicious ports being listened on.
    pub fn get_suspicious_ports(&self) -> Vec<u16> {
        self.known_ports
            .iter()
            .filter(|(_, info)| info.suspicious)
            .map(|(port, _)| *port)
            .collect()
    }

    /// Get ports by category.
    pub fn get_ports_by_category(&self, category: PortCategory) -> Vec<u16> {
        self.known_ports
            .iter()
            .filter(|(_, info)| info.category == category)
            .map(|(port, _)| *port)
            .collect()
    }
}

impl Default for SuspiciousPortDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_category_display() {
        assert_eq!(format!("{}", PortCategory::C2), "C2");
        assert_eq!(format!("{}", PortCategory::Rat), "RAT");
        assert_eq!(format!("{}", PortCategory::WellKnown), "Well-Known");
    }

    #[test]
    fn test_detector_creation() {
        let detector = SuspiciousPortDetector::new();
        assert!(!detector.known_ports.is_empty());
    }

    #[test]
    fn test_wellknown_ports() {
        let detector = SuspiciousPortDetector::new();

        let http = detector.analyze_port(80);
        assert_eq!(http.category, PortCategory::WellKnown);
        assert_eq!(http.service, Some("HTTP".to_string()));
        assert!(!http.suspicious);

        let https = detector.analyze_port(443);
        assert_eq!(https.category, PortCategory::WellKnown);
        assert!(!https.suspicious);

        let ssh = detector.analyze_port(22);
        assert_eq!(ssh.service, Some("SSH".to_string()));
    }

    #[test]
    fn test_suspicious_ports() {
        let detector = SuspiciousPortDetector::new();

        // Meterpreter default
        let meterpreter = detector.analyze_port(4444);
        assert!(meterpreter.suspicious);
        assert!(meterpreter.severity >= 75);

        // Back Orifice
        let bo = detector.analyze_port(31337);
        assert!(bo.suspicious);
        assert_eq!(bo.category, PortCategory::Backdoor);
        assert!(bo.severity >= 90);

        // njRAT
        let njrat = detector.analyze_port(5552);
        assert!(njrat.suspicious);
        assert_eq!(njrat.category, PortCategory::Rat);
    }

    #[test]
    fn test_unknown_port() {
        let detector = SuspiciousPortDetector::new();

        let unknown = detector.analyze_port(12398);
        assert_eq!(unknown.category, PortCategory::Unknown);
        assert!(unknown.service.is_none());
    }

    #[test]
    fn test_is_suspicious() {
        let detector = SuspiciousPortDetector::new();

        assert!(detector.is_suspicious(4444)); // Meterpreter
        assert!(detector.is_suspicious(31337)); // Back Orifice
        assert!(!detector.is_suspicious(80)); // HTTP
        assert!(!detector.is_suspicious(443)); // HTTPS
    }

    #[test]
    fn test_get_ports_by_category() {
        let detector = SuspiciousPortDetector::new();

        let rat_ports = detector.get_ports_by_category(PortCategory::Rat);
        assert!(!rat_ports.is_empty());
        assert!(rat_ports.contains(&4444) || rat_ports.contains(&5552));

        let wellknown = detector.get_ports_by_category(PortCategory::WellKnown);
        assert!(wellknown.contains(&80));
        assert!(wellknown.contains(&443));
    }

    #[test]
    fn test_miner_ports() {
        let detector = SuspiciousPortDetector::new();

        let stratum = detector.analyze_port(14444);
        assert!(stratum.suspicious);
        assert_eq!(stratum.category, PortCategory::Miner);
    }

    #[test]
    fn test_proxy_ports() {
        let detector = SuspiciousPortDetector::new();

        let tor = detector.analyze_port(9050);
        assert!(tor.suspicious);
        assert_eq!(tor.category, PortCategory::Proxy);
    }
}
