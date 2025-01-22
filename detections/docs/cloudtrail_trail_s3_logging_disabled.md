## Overview

Detect when an AWS CloudTrail trail is created without S3 logging enabled. Disabling S3 logging compromises visibility into access patterns and changes to log files, making it harder to detect unauthorized actions or tampering. Enabling S3 logging ensures audit trails are intact and supports robust security monitoring and compliance requirements.

**References**:
- [AWS Documentation: Configuring Amazon S3 Buckets for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- [AWS CLI Command: put-event-selectors](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/put-event-selectors.html)