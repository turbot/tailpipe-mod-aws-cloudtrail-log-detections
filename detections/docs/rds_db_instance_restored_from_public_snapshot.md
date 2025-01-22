## Overview

Detect when an Amazon RDS database was restored with public accessibility enabled. Restoring databases with public access exposes them to the internet, increasing the risk of unauthorized access, data breaches, and exploitation. Ensuring databases are restored with public access disabled protects data confidentiality and reduces the attack surface.

**References**:
- [Restoring a DB Instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html)
- [Controlling Access with Security Groups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
- [AWS CLI Command: restore-db-instance-from-db-snapshot](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/restore-db-instance-from-db-snapshot.html)
