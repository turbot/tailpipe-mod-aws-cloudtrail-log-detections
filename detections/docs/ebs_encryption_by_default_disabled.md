## Overview

Detect when Amazon Elastic Block Store (EBS) encryption by default was disabled in a region. Disabling default encryption increases the risk of unencrypted volumes being created inadvertently, exposing sensitive data to unauthorized access. Enabling default encryption simplifies management and ensures data at rest is consistently protected.

**References**:
- [Amazon EBS Encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
- [AWS CLI Command: disable-ebs-encryption-by-default](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.html)
