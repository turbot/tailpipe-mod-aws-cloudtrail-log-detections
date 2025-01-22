## Overview

Detect when an Amazon S3 bucket was configured to allow public access. Public access to S3 buckets exposes sensitive data to unauthorized users, increasing the risk of data breaches or misuse. Restricting public access ensures data confidentiality and integrity while maintaining compliance with security best practices.

**References**:
- [Controlling Public Access to S3 Buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [AWS CLI Command: get-bucket-policy-status](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3control/get-bucket-policy-status.html)
- [AWS CLI Command: put-public-access-block](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3control/put-public-access-block.html)