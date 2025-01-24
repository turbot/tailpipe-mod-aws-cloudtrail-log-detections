## Overview

Detect when the `AdministratorAccess` policy was attached to an IAM user. Assigning this policy grants full access to AWS resources, increasing the risk of unauthorized privilege escalation, security misconfigurations, or potential misuse. Monitoring these events helps enforce the principle of least privilege and ensures that administrative permissions are only assigned when necessary.

**References**:
- [AWS Documentation: Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-user-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-user-policy.html)
