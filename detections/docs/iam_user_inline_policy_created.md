## Overview

Detect when an inline policy was created and attached to an IAM user. Inline policies are directly embedded within users, making them harder to track and manage, which increases the risk of misconfigurations and excessive permissions. Monitoring these actions helps ensure secure and auditable permission management.

**References**:
- [Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: put-user-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/put-user-policy.html)
