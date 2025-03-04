## Overview

Detect when AWS CodeBuild projects experience repeated build failures. Multiple consecutive build failures within a short time period might indicate security issues such as:

- Potential software supply chain attacks targeting dependencies
- Injection of malicious code through compromised build scripts
- Security vulnerabilities being caught by static code analysis
- Configuration drift or permission issues disrupting the build pipeline

This detection focuses on projects with multiple failures, which may require immediate investigation to prevent disruption to development workflows or deployment of compromised code.

**References**:
- [AWS CodeBuild Security Best Practices](https://docs.aws.amazon.com/codebuild/latest/userguide/security-best-practices.html)
- [Building Secure CI/CD Pipelines](https://aws.amazon.com/blogs/devops/building-secure-ci-cd-pipelines/)
- [Troubleshooting AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html)
