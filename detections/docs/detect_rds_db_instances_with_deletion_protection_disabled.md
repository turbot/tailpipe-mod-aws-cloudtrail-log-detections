## Description

This detection identifies Amazon RDS database instances that have deletion protection disabled. Deletion protection prevents accidental or unauthorized deletion of database instances, ensuring the safety and availability of critical data. Disabling deletion protection increases the risk of unintentional data loss.

## Risks

When deletion protection is disabled, an RDS database instance can be inadvertently or maliciously deleted. Deleting a database instance results in the loss of the associated data and configurations, potentially leading to downtime, operational disruptions, and irreversible data loss.

Disabling deletion protection may also result in non-compliance with security policies or regulatory requirements that mandate safeguards to protect critical data. Enabling deletion protection ensures that database instances cannot be deleted without explicit, deliberate action, reducing the risk of human error and malicious activity.

## References

- [Deletion Protection for RDS Instances](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection)
- [AWS CLI Command: modify-db-instance](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html)