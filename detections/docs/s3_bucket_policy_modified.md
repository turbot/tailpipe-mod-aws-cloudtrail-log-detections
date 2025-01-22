## Overview

Detect when an Amazon S3 bucket policy was modified. Bucket policies define access permissions for resources within a bucket, and changes to these policies can introduce security risks, such as unauthorized access or overly permissive permissions, leading to potential data breaches. Reviewing these modifications ensures that access controls align with security best practices and compliance requirements.

**References**:
- [Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [AWS CLI Command: get-bucket-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/get-bucket-policy.html)
- [AWS CLI Command: put-bucket-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/put-bucket-policy.html)
