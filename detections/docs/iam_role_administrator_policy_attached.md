## Overview

Detect when the `AdministratorAccess` policy was attached to an IAM role. Assigning this policy grants full access to AWS resources, increasing the risk of unauthorized privilege escalation, security misconfigurations, or potential misuse. Monitoring these events ensures adherence to the principle of least privilege and helps maintain secure access management.

**References**:
- [AWS Documentation: Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-role-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-role-policy.html)
