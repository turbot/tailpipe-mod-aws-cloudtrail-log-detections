## Overview

Detect when an Amazon Elastic File System (EFS) file system's backup policy was disabled. Disabling a backup policy increases the risk of data loss and prolonged recovery times due to accidental deletions, corruption, or hardware failures. Enabling backup policies ensures data resilience, supports disaster recovery, and aligns with best practices for data protection.

**References**:
- [Backup and Restore for Amazon EFS](https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html)
- [AWS CLI Command: describe-backup-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/efs/describe-backup-policy.html)
- [AWS CLI Command: put-backup-policy](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/efs/put-backup-policy.html)