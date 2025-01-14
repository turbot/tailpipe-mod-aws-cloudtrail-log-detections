## Description

This detection identifies Amazon CloudFront distributions where default certificates are disabled. CloudFront distributions should use SSL/TLS certificates to secure connections and ensure encrypted communication between clients and CloudFront. Disabling default certificates may increase the risk of insecure communication.

## Risks

Disabling default certificates for CloudFront distributions can lead to unencrypted traffic, exposing sensitive data to interception or tampering during transmission. This is particularly critical for websites or applications handling personal data, financial transactions, or other confidential information.

Furthermore, not using SSL/TLS certificates for CloudFront distributions may lead to non-compliance with industry standards and regulatory requirements, such as PCI DSS, HIPAA, or GDPR. Adopting SSL/TLS for all CloudFront distributions is a key security best practice that ensures encrypted communication and improves customer trust.

## References

- [Using HTTPS with CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html)
- [Security Best Practices for CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DistributionSettings.SecureConnections)
- [Amazon CloudFront Best Practices](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/best-practices.html)
- [AWS CLI Command: get-distribution-config](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/get-distribution-config.html)
