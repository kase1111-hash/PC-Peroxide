# Contributing to PC-Peroxide

Thank you for your interest in contributing to PC-Peroxide! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/PC-Peroxide.git
   cd PC-Peroxide
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/kase1111-hash/PC-Peroxide.git
   ```

## Development Setup

### Prerequisites

- **Rust**: Install via [rustup](https://rustup.rs/) (Rust 1.70+ recommended)
- **Windows**: Required for full functionality testing (Windows APIs)
- **Git**: For version control

### Building the Project

```bash
# Build CLI (debug mode)
cargo build

# Build CLI (release mode)
cargo build --release

# Build GUI (requires gui feature)
cargo build --features gui

# Run tests
cargo test

# Run with logging enabled
RUST_LOG=debug cargo run -- scan --quick
```

### Windows-Specific Setup

On Windows, you can use the provided batch scripts:

```batch
# Setup dependencies
setup-windows.bat

# Build release version
build.bat

# Run quick scan
quick-scan.bat
```

## How to Contribute

### Types of Contributions

We welcome the following types of contributions:

- **Bug fixes**: Fix issues in existing code
- **New features**: Add new detection capabilities, scan types, or UI improvements
- **Documentation**: Improve README, add code comments, or create guides
- **Tests**: Add unit tests, integration tests, or test cases
- **Security research**: Report vulnerabilities or improve detection rules
- **YARA rules**: Contribute detection rules for new malware families

### What We're Looking For

- Detection engine improvements
- Performance optimizations
- Cross-platform compatibility (Linux/macOS support)
- Additional file format parsers
- Browser extension analyzers
- Network analysis capabilities

## Code Style Guidelines

### Rust Style

- Follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Use `cargo fmt` before committing
- Use `cargo clippy` to catch common mistakes
- Keep functions focused and small
- Document public APIs with doc comments

### Code Organization

```
src/
├── analysis/     # LLM-powered analysis
├── core/         # Core types, config, errors
├── detection/    # Detection engines (signatures, heuristics, YARA)
├── quarantine/   # Quarantine vault management
├── scanner/      # Scanning engines (file, process, network, etc.)
├── ui/           # CLI and GUI interfaces
└── utils/        # Utility functions
```

### Naming Conventions

- Use `snake_case` for functions, variables, and modules
- Use `PascalCase` for types and traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Prefer descriptive names over abbreviations

### Error Handling

- Use `thiserror` for defining custom errors
- Use `anyhow` for error propagation in application code
- Provide meaningful error messages
- Don't panic in library code

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests for a specific module
cargo test detection::
```

### Writing Tests

- Place unit tests in a `tests` module within the source file
- Place integration tests in the `tests/` directory
- Use meaningful test names that describe what's being tested
- Test both success and failure cases

### Test Categories

- **Unit tests**: Test individual functions and modules
- **Integration tests**: Test component interactions
- **Detection tests**: Verify malware detection accuracy
- **Performance tests**: Benchmark scan speeds and resource usage

## Submitting Changes

### Pull Request Process

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit with clear messages:
   ```bash
   git commit -m "Add feature: description of your changes"
   ```

3. Ensure all tests pass:
   ```bash
   cargo test
   cargo clippy
   cargo fmt --check
   ```

4. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

5. Open a Pull Request against the main repository

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Keep the first line under 72 characters
- Reference issues when applicable (e.g., "Fixes #123")

### Pull Request Guidelines

- Provide a clear description of the changes
- Include relevant issue numbers
- Add tests for new functionality
- Update documentation as needed
- Ensure CI passes before requesting review

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- PC-Peroxide version
- Operating system and version
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Any error messages or logs

### Feature Requests

When requesting features, please include:

- Clear description of the feature
- Use case and motivation
- Any relevant examples or mockups

### Security Issues

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## Questions?

If you have questions about contributing, feel free to:

- Open a GitHub issue with the "question" label
- Check existing issues and documentation

Thank you for contributing to PC-Peroxide!
