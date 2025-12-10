# Contributing to Hostname Attribution Guide

Thank you for your interest in contributing to this project! This guide provides resources for security teams to implement hostname attribution for malicious network connections.

## How to Contribute

### Reporting Issues

If you find errors, have suggestions, or want to request new content:

1. Check if an issue already exists
2. Create a new issue with a clear description
3. Include relevant details (OS version, tool versions, error messages)

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Test your configurations in a lab environment
5. Commit with clear messages (`git commit -m 'Add detection rule for X'`)
6. Push to your fork (`git push origin feature/improvement`)
7. Open a Pull Request

## Content Guidelines

### Documentation

- Use clear, technical language
- Include practical examples
- Provide both beginner-friendly explanations and advanced details
- Test all commands and configurations before submitting

### Configuration Files

- Include comments explaining each setting
- Provide safe defaults
- Note any security implications
- Include version requirements

### Detection Rules

- Follow Sigma rule format for cross-platform compatibility
- Include false positive guidance
- Provide MITRE ATT&CK mappings where applicable
- Test rules against sample data

## Code of Conduct

- Be respectful and constructive
- Focus on technical accuracy
- Help others learn and improve
- Credit original sources and research

## Areas for Contribution

### High Priority

- [ ] Additional detection rules for emerging threats
- [ ] Cloud-specific configurations (AWS, Azure, GCP)
- [ ] Container/Kubernetes monitoring examples
- [ ] Performance benchmarks for different environments

### Documentation

- [ ] Video tutorials
- [ ] Lab setup guides
- [ ] Troubleshooting guides
- [ ] Case studies

### Integrations

- [ ] Additional SIEM platform rules
- [ ] EDR integration guides
- [ ] Threat intelligence feed integration
- [ ] Automation playbooks

## Testing

Before submitting:

1. **Configuration files**: Test in isolated environment
2. **Detection rules**: Validate against sample logs
3. **Documentation**: Review for technical accuracy
4. **Scripts**: Test on target OS versions

## Questions?

Open an issue with the `question` label for any clarifications.

Thank you for helping improve security operations!
