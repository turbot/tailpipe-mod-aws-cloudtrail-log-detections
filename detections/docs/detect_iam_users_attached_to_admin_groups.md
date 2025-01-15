## Overview

Detect IAM users attached to groups with administrative privileges. Users in administrative groups have unrestricted access to AWS resources, increasing the risk of privilege escalation, unauthorized access, or accidental modifications. Monitoring these attachments helps enforce the principle of least privilege and prevents potential misuse of high-privilege accounts.

**References**:
- [IAM Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: add-user-to-group](https://docs.aws.amazon.com/cli/latest/reference/iam/add-user-to-group.html)