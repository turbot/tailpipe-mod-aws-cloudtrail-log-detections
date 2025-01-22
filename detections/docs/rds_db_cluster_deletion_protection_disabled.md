## Overview

Detect when an Amazon RDS database cluster had deletion protection disabled. Disabling deletion protection increases the risk of accidental or malicious deletions, potentially resulting in data loss, downtime, and operational disruptions. Enabling deletion protection helps maintain the integrity, availability, and resilience of critical database clusters.

**References**:
- [Deletion Protection for RDS Clusters](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_DeleteCluster.html#USER_DeleteCluster.DeletionProtection)
- [AWS CLI Command: modify-db-cluster](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/modify-db-cluster.html)
