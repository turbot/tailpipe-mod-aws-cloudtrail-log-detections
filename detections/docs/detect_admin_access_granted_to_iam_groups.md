## Overview

Detect instances where administrative access is granted to IAM groups. Admin-level permissions allow all group members unrestricted access to AWS resources, increasing the risk of unauthorized access, accidental modifications, or data exposure. Monitoring such changes helps enforce the principle of least privilege and ensures proper access control.

**References**:
- [Permissions Boundaries for IAM Entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-group-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-group-policy.html)

