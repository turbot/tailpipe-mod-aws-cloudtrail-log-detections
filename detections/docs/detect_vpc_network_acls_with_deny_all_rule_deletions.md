## Description

This detection identifies instances where "deny all" rules are deleted from network ACLs (NACLs) within a Virtual Private Cloud (VPC) in an AWS account. Network ACLs are essential for controlling traffic at the subnet level, and "deny all" rules act as a safeguard to block unwanted traffic when no other rules match.

## Risks

Deleting "deny all" rules from a network ACL can lead to unintended security vulnerabilities by allowing unfiltered traffic to flow through subnets. Without these default safeguard rules, malicious traffic or unauthorized access attempts may bypass intended restrictions, exposing resources to potential threats.

Such deletions may also indicate mismanagement or unauthorized activity within the account. An attacker could remove "deny all" rules to facilitate data exfiltration, enable lateral movement, or disrupt network traffic. Continuous monitoring of NACL configurations is crucial to prevent and detect these actions, ensuring the security of VPC resources.

## References

- [AWS Documentation: Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: delete-network-acl-entry](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-network-acl-entry.html)
