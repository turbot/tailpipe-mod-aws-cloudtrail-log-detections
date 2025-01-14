## Description

This detection identifies instances where an Amazon RDS database is restored with public accessibility enabled. Restoring a database with public access can expose the database to the internet, increasing the risk of unauthorized access and potential security breaches.

## Risks

Restoring an RDS database with public accessibility can make the database endpoint reachable from the internet. This exposure increases the risk of brute force attacks, data breaches, or exploitation of vulnerabilities in the database engine. Publicly accessible databases are especially vulnerable if they lack strong authentication mechanisms, encryption, or proper network security controls.

Enabling public access during a restore operation may also result in non-compliance with regulatory requirements or organizational policies that mandate the use of private, secure environments for sensitive data. Ensuring databases are restored with public access disabled helps protect data confidentiality and reduces the attack surface.

## References

- [Restoring a DB Instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html)
- [Controlling Access with Security Groups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
- [AWS CLI Command: restore-db-instance-from-db-snapshot](https://docs.aws.amazon.com/cli/latest/reference/rds/restore-db-instance-from-db-snapshot.html)
