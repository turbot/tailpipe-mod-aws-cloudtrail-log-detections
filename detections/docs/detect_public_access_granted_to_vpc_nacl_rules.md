## Description

This detection identifies network ACLs (NACLs) within a Virtual Private Cloud (VPC) that are configured to allow unrestricted public access. NACLs are a critical component of VPC security, controlling inbound and outbound traffic at the subnet level. Granting public access to a NACL can expose resources to unauthorized traffic and increase the risk of security breaches.

## Risks

Configuring a NACL to allow unrestricted access introduces significant security risks. Public access rules, such as allowing all IP ranges (0.0.0.0/0 for IPv4 or ::/0 for IPv6), can expose resources in the associated subnets to attacks like brute force, malware infiltration, or exploitation of vulnerabilities.

These overly permissive configurations may also signal accidental mismanagement or intentional malicious activity. An attacker could modify NACL rules to facilitate unauthorized access or disrupt legitimate network traffic. Continuous monitoring and restricting NACL rules to only necessary traffic sources are essential to maintaining a secure and compliant cloud environment.

## References

- [AWS Documentation: Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: describe-network-acls](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html)