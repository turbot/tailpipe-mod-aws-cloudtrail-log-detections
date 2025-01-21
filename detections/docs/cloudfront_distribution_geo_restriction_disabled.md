## Overview

Detect when a CloudFront distribution's geo-restriction is disabled. Disabling geo-restriction may lead to content being accessible in regions with compliance, licensing, or security restrictions, increasing the risk of misuse or piracy. Ensuring geo-restriction is properly configured helps align content delivery with business and regulatory requirements.

**References**:
- [Using Geo-Restriction to Restrict Access to Content](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html)
- [AWS CLI Command: get-distribution-config](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudfront/get-distribution-config.html)