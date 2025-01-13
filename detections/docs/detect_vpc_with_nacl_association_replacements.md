## Description

This detection identifies Virtual Private Clouds (VPCs) where network ACL (NACL) associations have been replaced. Network ACLs are an essential component for controlling traffic at the subnet level within a VPC. Replacing NACL associations can impact traffic flow and may indicate misconfigurations or unauthorized changes.

## Risks

Replacing NACL associations in a VPC can lead to unintended traffic disruptions or expose subnets to unauthorized access. If a new NACL is applied with overly permissive or restrictive rules, it could result in resources being left unprotected or becoming inaccessible. This is particularly critical in environments with stringent access control requirements or sensitive workloads.

NACL association replacements may also indicate potential security risks or malicious activity. An attacker with access to the account might replace NACLs to allow unauthorized traffic or disrupt legitimate communication. Without proper monitoring and auditing, these changes could compromise the security and functionality of your VPC.

## References

- [AWS Documentation: Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: replace-network-acl-association](https://docs.aws.amazon.com/cli/latest/reference/ec2/replace-network-acl-association.html)
