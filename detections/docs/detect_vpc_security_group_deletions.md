## Description

This detection identifies the deletion of security groups within a VPC in an AWS account. Security groups are critical for controlling inbound and outbound traffic to resources. Deleting a security group without proper oversight can disrupt access control and potentially expose resources to unauthorized traffic.

## Risks

The deletion of a security group can result in the loss of carefully defined traffic rules, leaving resources unprotected or inaccessible. This is especially critical if the deleted security group was actively assigned to resources, as it may cause disruptions in service availability or expose resources to unwanted traffic.

Security group deletions may also indicate potential mismanagement or malicious activity. An attacker with access to the account could delete security groups to bypass traffic restrictions, enabling lateral movement, data exfiltration, or other unauthorized actions. Without proper monitoring, these activities could go undetected until significant damage has occurred.

## References

- [AWS Documentation: Security Groups for Your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- [AWS CLI Command: delete-security-group](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-security-group.html)