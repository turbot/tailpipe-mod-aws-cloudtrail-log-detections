## Overview

Detect IAM users whose passwords have been reset by an administrator. Administrative password resets can indicate legitimate actions such as account recovery or security incidents but may also signal unauthorized activity or privilege misuse. Monitoring these events helps ensure account security and detect potential misuse.

**References**:
- [Managing Passwords for IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: update-login-profile](https://docs.aws.amazon.com/cli/latest/reference/iam/update-login-profile.html)
