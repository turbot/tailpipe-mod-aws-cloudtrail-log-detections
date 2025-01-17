## Overview

Detect Amazon RDS database instances configured to allow public access. Publicly accessible RDS instances expose databases to unauthorized access, increasing the risk of brute force attacks, data breaches, and compliance violations. Ensuring RDS instances are private and accessible only through secure networks protects sensitive data and reduces the attack surface.

**References**:
- [Modifying a DB Instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html)
- [Controlling Access with Security Groups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
- [AWS CLI Command: modify-db-instance](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html)
