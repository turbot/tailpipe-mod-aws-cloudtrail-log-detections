## Overview

Detect IAM users with inline policies attached. Inline policies are directly embedded within users, making them harder to manage and audit compared to managed policies, increasing the risk of excessive permissions or misconfigurations. Monitoring these policies ensures adherence to the principle of least privilege and secure access management.

**References**:
- [Inline Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: put-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/put-user-policy.html)
