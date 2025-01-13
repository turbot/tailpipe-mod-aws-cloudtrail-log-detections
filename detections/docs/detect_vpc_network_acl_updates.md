## Description

This detection identifies updates made to network ACLs (NACLs) within a Virtual Private Cloud (VPC) in an AWS account. NACLs play a crucial role in controlling inbound and outbound traffic at the subnet level. Unauthorized or unintended updates to NACLs can affect the security and functionality of the network.

## Risks

Updating a network ACL can introduce risks such as misconfigured rules that either allow unauthorized traffic or block legitimate traffic. For example, adding overly permissive rules can expose resources to external threats, while overly restrictive rules can disrupt communication between resources or external systems.

Unauthorized changes to NACLs may indicate malicious activity or accidental mismanagement. An attacker with access to the account could modify NACL rules to enable unauthorized access, exfiltrate data, or disrupt network traffic. Monitoring NACL updates ensures that only authorized changes are made and that the security and operational integrity of the VPC are maintained.

## References

- [AWS Documentation: Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: describe-network-acls](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html)
