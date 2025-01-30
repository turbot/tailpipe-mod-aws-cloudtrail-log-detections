## Overview

Detect when managed policy was attached to IAM roles. Managed policies are standalone policies that can be attached to multiple identities, such as users, groups, and roles. Over-permissive or unmanaged policies can grant excessive access to sensitive resources, increasing the risk of privilege escalation, unauthorized access, or accidental modifications. 

Regularly monitoring these attachments ensures adherence to the principle of least privilege, reduces the attack surface, and supports compliance with security best practices.

**References**:
- [Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [AWS CLI Command: attach-role-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-role-policy.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
