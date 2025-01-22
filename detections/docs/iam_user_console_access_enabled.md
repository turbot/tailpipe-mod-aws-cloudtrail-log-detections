## Overview

Detect when an IAM user was granted AWS Management Console access. Console access increases the risk of unauthorized changes or data exposure if proper security controls, such as MFA and strong password policies, are not enforced. Monitoring these configurations ensures that only authorized and secured users have console access.

**References**:
- [Enabling or Disabling a User’s Console Access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_enable-user.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI Command: create-login-profile](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/create-login-profile.html)
