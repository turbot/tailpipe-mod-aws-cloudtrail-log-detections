## Overview

Detect IAM users that have been granted public access. Allowing unauthorized users to access AWS resources through IAM users exposes your environment to risks like data exfiltration, privilege escalation, and configuration manipulation. Publicly accessible IAM users are a critical security concern that undermines the principle of least privilege and increases the attack surface.

**References**:
- [IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-user-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-user-policy.html)