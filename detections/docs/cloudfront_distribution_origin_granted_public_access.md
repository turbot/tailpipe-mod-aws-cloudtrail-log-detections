## Overview

Detect when a CloudFront distribution origin is configured to allow unrestricted public access. Publicly accessible origins expose backend systems to unauthorized access, increasing the risk of data breaches, abuse, and exploitation. Implementing proper access controls ensures security and compliance by restricting access to authorized requests only.

**References**:
- [Restricting Access to Origins](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-origin.html)
- [CloudFront Signed URLs and Cookies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-urls.html)
- [AWS CLI Command: update-distribution](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudfront/update-distribution.html)