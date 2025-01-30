## Overview

Detect when an Amazon RDS database instance had deletion protection disabled. Disabling deletion protection increases the risk of accidental or malicious deletions, potentially leading to data loss, downtime, and operational disruptions. Enabling deletion protection safeguards critical data and ensures secure database management.

**References**:
- [Deletion Protection for RDS Instances](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection)
- [AWS CLI Command: modify-db-instance](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/modify-db-instance.html)
