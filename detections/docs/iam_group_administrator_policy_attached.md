## Overview

Detect when the `AdministratorAccess` policy was attached to an IAM group. Assigning this policy grants all group members full access to AWS resources, increasing the risk of unauthorized privilege escalation, security misconfigurations, or potential misuse. Monitoring these actions ensures that administrative permissions are only assigned when necessary and adheres to the principle of least privilege.

**References**:
- [AWS Documentation: Managed Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-group-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-group-policy.html)
