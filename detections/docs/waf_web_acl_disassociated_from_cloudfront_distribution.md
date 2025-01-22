## Overview

Detect when a Web Application Firewall (WAF) ACL was disassociated from an Amazon CloudFront distribution. Disassociating a WAF ACL removes protections against threats like SQL injection and cross-site scripting (XSS), exposing the distribution to potential attacks. Maintaining WAF ACL associations is critical to securing the CloudFront distribution and mitigating threats.

**References**:
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
- [Best Practices for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/best-practices.html)
- [AWS CLI Command: update-distribution](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudfront/update-distribution.html)
