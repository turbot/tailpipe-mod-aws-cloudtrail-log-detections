## Overview

Detect when a managed policy was attached to an IAM user. Attaching managed policies directly to users bypasses group-based access control mechanisms, making permissions harder to manage and audit. Over-permissioned policies increase the risk of privilege escalation, unauthorized access, or accidental resource modifications. Monitoring these actions ensures adherence to best practices, such as using IAM groups for permissions management and enforcing the principle of least privilege.

**References**:
- [Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: attach-user-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-user-policy.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

