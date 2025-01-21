## Overview

Detect the upload of compressed files, such as `.zip`, `.tar.gz`, or `.7z`, to Amazon S3 buckets. Compressed uploads can be part of routine operations but may also indicate attempts to obscure data or enable large-scale transfers. Identifying these activities ensures adherence to data handling policies and mitigates potential security risks.

**References**:
- [Logging and Monitoring in Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/MonitoringOverview.html)
- [Best Practices for Securing S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS CLI Command: put-object](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-object.html)
