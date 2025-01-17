## Overview

Detect when a Web Application Firewall (WAF) ACL is disassociated from an Amazon CloudFront distribution. Removing a WAF ACL eliminates protections against threats like SQL injection and cross-site scripting (XSS), leaving the distribution vulnerable. Ensuring WAF ACLs remain associated helps maintain robust security for your CloudFront distributions.

**References**:
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
- [Best Practices for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/best-practices.html)
- [AWS CLI Command: update-distribution](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/update-distribution.html)
