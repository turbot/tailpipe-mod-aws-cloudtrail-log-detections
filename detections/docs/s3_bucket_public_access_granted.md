## Description

This detection identifies Amazon S3 buckets that are configured to allow public access. Public access to S3 buckets can expose sensitive data to unauthorized users and increase the risk of data breaches or misuse. Monitoring and restricting public access ensures data confidentiality and integrity.

## Risks

Granting public access to S3 buckets poses significant security risks. Unauthorized users can view, modify, or delete data stored in publicly accessible buckets. This is particularly critical if the bucket contains sensitive information such as personal data, financial records, or intellectual property.

In addition, public access to S3 buckets can lead to compliance violations with industry standards and regulations, such as GDPR, HIPAA, or PCI DSS, which mandate strict control over data exposure. Ensuring that S3 buckets are private or accessible only to trusted entities is essential for maintaining a secure cloud environment.

## References

- [Controlling Public Access to S3 Buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [AWS CLI Command: get-bucket-policy-status](https://docs.aws.amazon.com/cli/latest/reference/s3control/get-bucket-policy-status.html)
- [AWS CLI Command: put-public-access-block](https://docs.aws.amazon.com/cli/latest/reference/s3control/put-public-access-block.html)
