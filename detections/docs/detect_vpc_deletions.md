## Description

This detection identifies the deletion of Virtual Private Clouds (VPCs) in an AWS account. Monitoring VPC deletions is crucial to ensure that critical resources are not inadvertently removed and to maintain the integrity of the network architecture. Unauthorized or unplanned VPC deletions can disrupt services and compromise security.

## Risks

Deleting a VPC without proper validation can result in the loss of critical resources and associated configurations, such as subnets, route tables, network ACLs, and internet gateways. This can lead to service outages or disruptions, particularly if the VPC is hosting production workloads or interconnected with other environments.

Additionally, VPC deletions may indicate potential mismanagement or malicious activity within the account. Without appropriate monitoring, an attacker with access to the account could delete VPCs as part of a broader effort to disrupt operations or erase evidence of unauthorized access.

## References

- [AWS Documentation: Deleting a VPC](https://docs.aws.amazon.com/vpc/latest/userguide/working-with-vpcs.html#DeleteVPC)
- [AWS CLI Command: delete-vpc](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-vpc.html)
