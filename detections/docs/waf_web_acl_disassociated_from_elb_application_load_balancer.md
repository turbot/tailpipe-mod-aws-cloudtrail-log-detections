## Overview

Detect instances where a Web Application Firewall (WAF) ACL is disassociated from an Application Load Balancer (ALB). Disassociating a WAF ACL removes protective rules that safeguard web applications from attacks such as SQL injection or cross-site scripting (XSS). Monitoring these changes ensures that critical protections remain in place and unauthorized disassociations are identified promptly.

**References**:
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
- [Best Practices for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/best-practices.html)
- [AWS CLI Command: disassociate-web-acl](https://docs.aws.amazon.com/cli/latest/reference/wafv2/disassociate-web-acl.html)