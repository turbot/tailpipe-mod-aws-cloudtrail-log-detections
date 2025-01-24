## Overview

Detect when an inline policy was created and attached to an IAM role. Inline policies are directly embedded within roles, making them harder to track and audit compared to managed policies, increasing the risk of misconfigurations and excessive permissions. Identifying these actions ensures secure configurations and adherence to the principle of least privilege.

**References**:
- [Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: put-role-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/put-role-policy.html)
