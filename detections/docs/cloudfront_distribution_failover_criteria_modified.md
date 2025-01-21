## Overview

Detect when failover criteria in a CloudFront distribution is modified. Unapproved changes to failover settings can disrupt service reliability by preventing proper failover during origin failures or causing unnecessary failovers. Monitoring these changes ensures robust failover configurations and maintains the availability of critical services.

**References**:
- [Origin Groups for CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/high_availability_origin_failover.html)
- [AWS CLI Command: get-distribution-config](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudfront/get-distribution-config.html)