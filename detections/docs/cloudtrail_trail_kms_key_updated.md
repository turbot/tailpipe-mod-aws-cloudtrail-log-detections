<!-- Restricting to CLI-based events, as console requests show all fields while CLI only shows updated fields. -->

## Overview

Detect when an AWS CloudTrail trail was updated with a new AWS Key Management Service (KMS) key. Changes to the KMS key may disrupt log encryption or decryption, potentially resulting in data loss or logging interruptions. Monitoring these updates ensures encryption integrity and protects against unauthorized modifications.

**References**:
- [Encrypting CloudTrail Logs with AWS KMS](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
- [AWS CLI Command: update-trail](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/update-trail.html)