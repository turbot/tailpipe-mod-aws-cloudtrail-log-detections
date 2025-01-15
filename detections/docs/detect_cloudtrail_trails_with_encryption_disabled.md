## Overview

Detect AWS CloudTrail trails with encryption disabled. Disabling encryption increases the risk of log data exposure, making sensitive account activity vulnerable to unauthorized access or tampering. Enabling encryption ensures secure log storage and helps meet compliance requirements for protecting sensitive operational data.

**References**:
- [Encrypting CloudTrail Logs with AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-kms.html)
- [Amazon S3 Server-Side Encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html)
- [AWS CLI Command: update-trail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
