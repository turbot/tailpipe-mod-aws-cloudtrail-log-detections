## Overview

Detect Amazon CloudFront distributions with default certificates disabled. Disabling default SSL/TLS certificates increases the risk of insecure communication by exposing sensitive data to interception or tampering during transmission. Ensuring encrypted communication with SSL/TLS is critical for protecting sensitive information and maintaining compliance with industry standards.

**References**:
- [Using HTTPS with CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html)
- [Security Best Practices for CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DistributionSettings.SecureConnections)
- [Amazon CloudFront Best Practices](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/best-practices.html)
- [AWS CLI Command: get-distribution-config](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/get-distribution-config.html)
