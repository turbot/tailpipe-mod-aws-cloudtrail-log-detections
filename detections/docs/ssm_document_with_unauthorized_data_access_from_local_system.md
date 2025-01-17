## Overview

Detect AWS Systems Manager (SSM) documents that facilitate unauthorized data access from local systems. Misconfigured or malicious SSM documents can be used to extract sensitive data from AWS resources to local systems, posing a significant security risk. Monitoring these documents ensures that access is restricted to authorized systems and aligns with security best practices.

**References**:
- [AWS Systems Manager Documents](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-ssm-docs.html)
- [Best Practices for AWS Systems Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/best-practices.html)
- [AWS CLI Command: get-document](https://docs.aws.amazon.com/cli/latest/reference/ssm/get-document.html)