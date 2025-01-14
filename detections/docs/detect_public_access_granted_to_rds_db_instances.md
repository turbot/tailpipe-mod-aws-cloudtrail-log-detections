## Description

This detection identifies Amazon RDS database instances that are configured to allow public access. Publicly accessible RDS instances expose the database to the internet, increasing the risk of unauthorized access and potential security breaches.

## Risks

Granting public access to RDS database instances significantly increases the risk of brute force attacks, unauthorized access, and data breaches. Publicly exposed databases can also be targeted by malicious actors seeking to exploit vulnerabilities or misconfigurations.

In addition, public access may lead to compliance violations with regulatory frameworks and industry standards, such as PCI DSS, GDPR, or HIPAA, which require strict control over data exposure. Ensuring that RDS instances are private and accessible only through secure networks reduces the attack surface and protects sensitive data.

## References

- [Modifying a DB Instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html)
- [Controlling Access with Security Groups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
- [AWS CLI Command: modify-db-instance](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html)
