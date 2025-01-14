## Description

This detection identifies Amazon Elastic File System (EFS) file systems that have the backup policy disabled. Enabling backup policies ensures that file system data is automatically backed up using AWS Backup, protecting against accidental deletion, corruption, or ransomware attacks. 

## Risks

Disabling the backup policy for EFS file systems can lead to data loss or prolonged recovery times in the event of accidental deletions, corruption, or hardware failures. Without backups, recovering data from an EFS file system may be impossible, particularly for critical applications or workloads.

Not having a backup policy in place can increase the risk of data loss and may fail to meet regulatory requirements or policies that mandate robust data protection and recovery measures. Enabling backup policies for all EFS file systems is critical for ensuring data resilience, supporting disaster recovery efforts, and adhering to established standard

## References

- [Backup and Restore for Amazon EFS](https://docs.aws.amazon.com/efs/latest/ug/awsbackup.html)
- [AWS CLI Command: describe-backup-policy](https://docs.aws.amazon.com/cli/latest/reference/efs/describe-backup-policy.html)
- [AWS CLI Command: put-backup-policy](https://docs.aws.amazon.com/cli/latest/reference/efs/put-backup-policy.html)
