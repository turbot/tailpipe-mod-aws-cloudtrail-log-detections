## Overview

Detect instances where email sending is enabled for an Amazon Simple Email Service (SES) identity. Enabling sending for identities such as domains or email addresses introduces the potential risk of phishing attacks if unauthorized users gain access to SES. Monitoring this setting helps ensure that only trusted identities are used for outbound emails, preventing abuse of your email infrastructure.

**References**:
- [Verifying Identities in Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html)
- [Best Practices for Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/best-practices.html)
- [AWS CLI Command: verify-domain-identity](https://docs.aws.amazon.com/cli/latest/reference/ses/verify-domain-identity.html)