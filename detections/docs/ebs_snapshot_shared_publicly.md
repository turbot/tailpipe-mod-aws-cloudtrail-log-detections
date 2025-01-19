## Overview

Detect when an Amazon Elastic Block Store (EBS) snapshot was shared publicly. Public snapshots expose sensitive data to unauthorized users, increasing the risk of data breaches and misuse. Ensuring snapshots are private or shared only with trusted accounts is critical for maintaining data security and compliance.

**References**:
- [Sharing Amazon EBS Snapshots](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html)
- [AWS CLI Command: modify-snapshot-attribute](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/modify-snapshot-attribute.html)
