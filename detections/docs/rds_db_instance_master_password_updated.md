## Overview

Detect when the master password for an Amazon RDS database instance was updated. Unauthorized or unmonitored password changes can disrupt operations, compromise database access, or indicate malicious intent. Monitoring password updates ensures the confidentiality, availability, and integrity of the database.

**References**:
- [Resetting the Master User Password](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html)
- [AWS CLI Command: modify-db-instance](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/modify-db-instance.html)
