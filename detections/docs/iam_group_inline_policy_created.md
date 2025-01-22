## Overview

Detect when an inline policy was created and attached to an IAM group. Inline policies are embedded directly within groups and are harder to manage and audit compared to managed policies, increasing the risk of misconfigurations and excessive permissions. Identifying these actions helps enforce the principle of least privilege and maintain secure access configurations.

**References**:
- [Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: put-group-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/put-group-policy.html)
