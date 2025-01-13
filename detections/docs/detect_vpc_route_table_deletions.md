## Description

This detection identifies the deletion of route tables within a Virtual Private Cloud (VPC) in an AWS account. Route tables are essential for directing network traffic to its intended destinations. Deleting a route table can disrupt traffic flow and may indicate misconfigurations or unauthorized changes.

## Risks

Deleting a route table can result in significant connectivity issues within a VPC. Without an appropriate route table, traffic within subnets may fail to reach its intended destinations, causing disruptions to applications and services. This is particularly critical for subnets handling public or external-facing traffic.

Additionally, route table deletions may signify malicious activity or mismanagement. An attacker with access to the account could delete a route table to disrupt services or isolate resources. Without adequate monitoring, such actions could compromise the availability and security of your network infrastructure.

## References

- [AWS Documentation: Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: delete-route-table](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-route-table.html)
