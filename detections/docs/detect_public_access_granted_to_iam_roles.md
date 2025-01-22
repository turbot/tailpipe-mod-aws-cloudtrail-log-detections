## Overview

Detect IAM roles that have been granted public access. Allowing unauthorized users to assume roles exposes AWS resources to risks such as data exfiltration, privilege escalation, or resource misuse. Publicly accessible IAM roles weaken your security posture and are a common cause of security incidents in cloud environments.

**References**:
- [IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: attach-role-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/attach-role-policy.html)
