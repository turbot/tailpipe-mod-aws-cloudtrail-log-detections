## Overview

Detect IAM groups that have been granted public access. Publicly accessible groups allow unauthorized users to access AWS resources, leading to risks like data breaches or privilege escalation. Monitoring these configurations ensures permissions adhere to the principle of least privilege and restrict access to trusted entities.

**References**:
- [Identity and Access Management (IAM) Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-group-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-group-policy.html)