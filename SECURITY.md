# Security Policy

## Supported Versions

The following versions of PC-Peroxide are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in PC-Peroxide, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Send an email to the maintainers with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Include

Please provide as much information as possible:

- **Type of vulnerability** (e.g., code execution, privilege escalation, bypass)
- **Affected components** (e.g., scanner, quarantine, signature updates)
- **Attack vector** (local, network, requires user interaction)
- **Proof of concept** (if available)
- **Affected versions**

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 7 days
- **Resolution Timeline**: We aim to resolve critical vulnerabilities within 30 days
- **Credit**: We will credit reporters in our security advisories (unless anonymity is requested)

### Scope

The following are in scope for security reports:

- **Detection bypass**: Methods to evade malware detection
- **Quarantine escape**: Ways to escape or bypass the quarantine vault
- **Signature tampering**: Unauthorized modification of signature databases
- **Privilege escalation**: Gaining elevated permissions through the tool
- **Code execution**: Remote or local code execution vulnerabilities
- **Information disclosure**: Unauthorized access to sensitive data

### Out of Scope

- Issues in third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Denial of service attacks
- Issues requiring physical access to the machine
- Theoretical vulnerabilities without proof of concept

## Security Best Practices

When using PC-Peroxide:

### For Users

- Download only from official sources (GitHub releases)
- Verify file integrity using provided checksums
- Keep signatures updated regularly
- Run with appropriate privileges (admin for full scans)
- Review quarantined items before permanent deletion

### For Developers

- Sign commits with GPG keys
- Review all pull requests for security implications
- Use `cargo audit` to check for vulnerable dependencies
- Follow secure coding practices
- Never commit sensitive data (API keys, credentials)

## Security Features

PC-Peroxide implements several security measures:

- **Quarantine encryption**: AES-256-GCM encryption for isolated threats
- **Integrity checking**: Signature database verification
- **Secure deletion**: Multi-pass file overwrite before deletion
- **Local-first operation**: No required network connectivity
- **Transparent operation**: Clear logging of all actions

## Known Security Considerations

### Signature Updates

- Updates are fetched over HTTPS
- Signature files should be verified before applying
- Offline operation is fully supported

### Quarantine Vault

- Files are encrypted with AES-256-GCM
- Encryption keys are derived per-installation
- Quarantined files cannot execute

### False Positives

- Whitelist by hash (not path) for security
- Review all detections before taking action
- Use heuristic sensitivity settings appropriately

## Acknowledgments

We thank the security researchers who have helped improve PC-Peroxide:

*No security vulnerabilities have been reported yet.*

---

Thank you for helping keep PC-Peroxide and its users safe!
