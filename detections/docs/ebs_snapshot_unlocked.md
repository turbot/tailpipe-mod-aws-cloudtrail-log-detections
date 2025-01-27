## Overview

Detect when an Amazon Elastic Block Store (EBS) snapshot was unlocked. Unlocking a snapshot allows access to its data for a specified duration, which could expose sensitive information if not properly monitored or managed. Monitoring these actions helps ensure data security and compliance with access control policies.

**References**:
- [EBS Snapshot Overview](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-snapshots.html)
- [AWS CLI Command: unlock-snapshot](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/unlock-snapshot.html)
