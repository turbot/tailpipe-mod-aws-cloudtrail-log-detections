## Overview

Detect when an Amazon Simple Email Service (SES) identity was enabled for email sending. Enabling email sending for identities, such as domains or email addresses, introduces potential risks of phishing attacks if unauthorized users gain access to SES. Monitoring this setting ensures that only trusted identities are used for outbound emails, protecting your email infrastructure from abuse.

**References**:
- [Verifying Identities in Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html)
- [Best Practices for Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/best-practices.html)
- [AWS CLI Command: verify-domain-identity](https://docs.aws.amazon.com/cli/latest/reference/ses/verify-domain-identity.html)