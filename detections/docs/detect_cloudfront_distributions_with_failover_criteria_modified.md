## Description

This detection identifies modifications to the failover criteria in Amazon CloudFront distributions. Failover criteria define the conditions under which CloudFront will switch to a secondary origin to maintain service availability. Unauthorized or unintended changes to these criteria may disrupt failover behavior and impact service reliability.

## Risks

Modifying failover criteria in a CloudFront distribution can lead to unexpected behavior during origin failures, potentially resulting in service outages or degraded performance. For example, overly restrictive failover conditions may prevent CloudFront from switching to a healthy backup origin, while overly permissive conditions might lead to unnecessary failovers.

Unapproved changes to failover criteria could also indicate malicious activity or mismanagement, jeopardizing the reliability and availability of services. Ensuring that failover configurations are aligned with best practices and regularly monitored helps maintain a robust and resilient distribution setup.

## References

- [Origin Groups for CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/high_availability_origin_failover.html)
- [AWS CLI Command: get-distribution-config](https://docs.aws.amazon.com/cli/latest/reference/cloudfront/get-distribution-config.html)
