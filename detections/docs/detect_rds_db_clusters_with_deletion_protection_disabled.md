## Description

This detection identifies Amazon RDS database clusters that have deletion protection disabled. Deletion protection is a safeguard to prevent accidental or unauthorized deletion of critical database clusters. Disabling deletion protection increases the risk of data loss and operational disruptions.

## Risks

Disabling deletion protection for RDS database clusters can lead to unintended deletions, either due to human error or malicious activity. Deleting a database cluster removes all associated instances and data, potentially resulting in significant downtime, loss of critical information, and operational disruptions.

Without deletion protection, organizations may also fail to meet compliance and security policies that require safeguards to prevent data loss. Ensuring that deletion protection is enabled for all critical database clusters is essential to maintaining data integrity, availability, and resilience.

## References

- [Deletion Protection for RDS Clusters](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_DeleteCluster.html#USER_DeleteCluster.DeletionProtection)
- [AWS CLI Command: modify-db-cluster](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-cluster.html)
