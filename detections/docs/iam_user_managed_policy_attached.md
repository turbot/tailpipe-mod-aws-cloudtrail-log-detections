## Overview

Detect when managed policies were attached to IAM users. Managed policies are standalone policies that provide a reusable and scalable way to assign permissions. However, attaching managed policies directly to users bypasses group-based access control mechanisms, making permissions harder to manage and audit. 

Over-permissioned policies can increase the risk of privilege escalation, unauthorized access, or accidental resource modifications. Monitoring these actions helps enforce best practices, such as using IAM groups for permissions management and adhering to the principle of least privilege.

Using managed policies for individual users also complicates governance, as updates to a managed policy affect all attached users, potentially leading to unintended consequences. Monitoring managed policies attached to IAM users helps enforce best practices, such as using IAM groups for permissions management and ensuring compliance with the principle of least privilege.

**References**:
- [AWS Documentation: Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: attach-user-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-user-policy.html)
- [AWS Documentation: IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
