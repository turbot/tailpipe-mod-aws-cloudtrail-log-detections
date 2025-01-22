## Overview

Detect when an AWS CloudTrail trail is created without encryption enabled. Disabling encryption increases the risk of log data exposure, making sensitive account activity vulnerable to unauthorized access or tampering. Enabling encryption ensures secure log storage and helps meet compliance requirements for protecting sensitive operational data.

**References**:
- [Encrypting CloudTrail Logs with AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-kms.html)
- [AWS CLI Command: update-trail](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/update-trail.html)