## Description

This detection identifies modifications to Amazon S3 bucket policies. S3 bucket policies define access permissions for resources within a bucket. Monitoring changes to bucket policies is critical to ensure that access controls remain aligned with security best practices and compliance requirements.

## Risks

Modifications to S3 bucket policies can introduce security risks, such as overly permissive access that allows unauthorized users or services to access sensitive data. For example, granting public read or write access to a bucket may expose its contents to the internet, leading to potential data breaches or misuse.

Unauthorized or accidental changes to bucket policies may also disrupt application functionality or violate regulatory requirements. Regular monitoring of bucket policy modifications ensures that changes are authorized, documented, and do not compromise the security or integrity of the data stored in the bucket.

## References

- [Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [AWS CLI Command: get-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html)
- [AWS CLI Command: put-bucket-policy](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-policy.html)
