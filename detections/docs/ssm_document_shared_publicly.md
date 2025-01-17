## Overview

Detect instances where public access is granted to AWS Systems Manager (SSM) documents. Publicly accessible SSM documents can expose sensitive configurations, scripts, or automation tasks to unauthorized users. Identifying such configurations ensures that access controls align with the principle of least privilege and prevent misuse or unauthorized changes.

**References**:
- [AWS Systems Manager Documents](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-ssm-docs.html)
- [Best Practices for AWS Systems Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/best-practices.html)
- [AWS CLI Command: modify-document-permission](https://docs.aws.amazon.com/cli/latest/reference/ssm/modify-document-permission.html)