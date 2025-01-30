## Overview

Detect when a Web Application Firewall (WAF) ACL was disassociated from an Application Load Balancer (ALB). Disassociating a WAF ACL removes protective rules that safeguarded web applications from attacks such as SQL injection or cross-site scripting (XSS). Maintaining WAF ACL associations is critical to ensuring application security and mitigating potential threats.

**References**:
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
- [Best Practices for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/best-practices.html)
- [AWS CLI Command: disassociate-web-acl](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/wafv2/disassociate-web-acl.html)
