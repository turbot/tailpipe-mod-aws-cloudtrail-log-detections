## Overview

Detect Amazon RDS database clusters with deletion protection disabled. Disabling deletion protection increases the risk of accidental or malicious deletions, leading to data loss, downtime, and operational disruptions. Enabling deletion protection ensures the integrity, availability, and resilience of critical database clusters.

**References**:
- [Deletion Protection for RDS Clusters](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_DeleteCluster.html#USER_DeleteCluster.DeletionProtection)
- [AWS CLI Command: modify-db-cluster](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-cluster.html)
