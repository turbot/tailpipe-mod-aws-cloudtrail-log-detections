## Overview

Detect modifications to Amazon Simple Email Service (SES) identity policies that introduce wildcard permissions or allow access to external accounts. Wildcard permissions (e.g., `*`) and external access can expose SES resources to unauthorized use, leading to email spoofing, spam, or abuse of your email-sending capabilities. Identifying such changes ensures that policies remain secure and adhere to best practices.

**References**:
- [Amazon SES Identity Policies](https://docs.aws.amazon.com/ses/latest/dg/using-identity-policies.html)
- [Best Practices for Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/best-practices.html)
- [AWS CLI Command: put-identity-policy](https://docs.aws.amazon.com/cli/latest/reference/ses/put-identity-policy.html)
