## Overview

Detect IAM users added to groups with administrative privileges. Admin groups grant unrestricted access to AWS resources, increasing the risk of privilege escalation, resource misuse, or account-wide breaches. Monitoring these actions ensures elevated privileges are assigned only when necessary and adhere to security best practices.

**References**:
- [IAM Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: add-user-to-group](https://docs.aws.amazon.com/cli/latest/reference/iam/add-user-to-group.html)
