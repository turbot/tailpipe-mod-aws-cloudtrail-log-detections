## Overview

Detect when an Amazon RDS database instance had IAM database authentication disabled. Disabling IAM authentication increases the risk of credential leakage and unauthorized access by relying on static credentials. Enabling IAM authentication simplifies access management, enhances security, and aligns with best practices.

**References**:
- [IAM Database Authentication for MySQL and PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)
- [Securing Amazon RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.Security.html)
- [AWS CLI Command: modify-db-instance](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/modify-db-instance.html)
