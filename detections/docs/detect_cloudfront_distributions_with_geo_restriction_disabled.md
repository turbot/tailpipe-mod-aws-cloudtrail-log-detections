## Description

This detection identifies Amazon CloudFront distributions where geo-restriction is disabled. Geo-restriction allows you to control access to content based on the geographic location of the viewer. Disabling geo-restriction may lead to content being accessible in regions where access should be restricted due to compliance, licensing, or security concerns.

## Risks

When geo-restriction is disabled, content may be delivered to regions where access is restricted by regulatory or contractual obligations. This could result in non-compliance with laws or agreements, leading to potential fines, legal disputes, or reputational damage.

Additionally, disabling geo-restriction may expose content to unauthorized users in high-risk regions, increasing the likelihood of misuse, piracy, or malicious activity. Properly configuring geo-restriction ensures that content delivery is aligned with business, compliance, and security requirements.

## References

- [Using Geo-Restriction to Restrict Access to Content](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html)
- [AWS CLI Command: get-distribution-config](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/get-distribution-config.html)
