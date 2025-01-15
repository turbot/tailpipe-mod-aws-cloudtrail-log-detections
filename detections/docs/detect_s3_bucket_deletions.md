## Description

This detection identifies instances where Amazon S3 buckets are deleted. S3 buckets are often used to store critical data, logs, backups, and other important resources. Monitoring bucket deletions is essential to prevent accidental or unauthorized data loss.

## Risks

Deleting an S3 bucket removes all its contents and configurations, resulting in permanent data loss if the data is not backed up or replicated elsewhere. Unauthorized or accidental bucket deletions can disrupt operations, impact application functionality, and lead to potential compliance violations.

In addition, bucket deletions may indicate malicious activity, such as an attacker attempting to erase evidence of their actions or disrupt services. Regular monitoring of bucket deletions ensures that only authorized deletions occur and that critical data remains protected.

## References

- [Deleting an S3 Bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/delete-bucket.html)
- [AWS CLI Command: delete-bucket](https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-bucket.html)
