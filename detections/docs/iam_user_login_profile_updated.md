## Overview

Detect when an IAM user's password was reset by an administrator. Administrative password resets may indicate legitimate actions, such as account recovery or responses to security incidents, but could also signal unauthorized activity or privilege misuse. Monitoring these events helps maintain account security and detect potential misuse.

**References**:
- [Managing Passwords for IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: update-login-profile](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/update-login-profile.html)
