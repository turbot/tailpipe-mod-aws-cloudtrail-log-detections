## Overview

Detect when a compressed file, such as `.zip`, `.tar.gz`, or `.7z`, was uploaded to an Amazon S3 bucket. Compressed uploads may be part of routine operations but could also indicate attempts to obscure data or facilitate large-scale transfers. Ensuring these uploads align with data handling policies helps mitigate potential security risks.

**References**:
- [Logging and Monitoring in Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/MonitoringOverview.html)
- [AWS CLI Command: put-object](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/put-object.html)
