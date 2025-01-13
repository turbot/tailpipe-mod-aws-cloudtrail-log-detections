## Description

This detection identifies instances where route table associations have been replaced within a Virtual Private Cloud (VPC) in an AWS account. Route table associations determine how traffic is routed for subnets in a VPC. Replacing these associations can impact network traffic flow and may indicate unauthorized changes or misconfigurations.

## Risks

Replacing a route table association can result in traffic being routed incorrectly or blocked entirely. This can disrupt communication between resources, impact application availability, or expose sensitive resources to unintended access. These risks are particularly significant in environments with complex network architectures or strict traffic control requirements.

Furthermore, unauthorized changes to route table associations may be indicative of malicious activity. An attacker with access to the account could modify associations to redirect traffic, isolate resources, or disrupt operations. Without monitoring, such actions could compromise the security and availability of your network infrastructure.

## References

- [AWS Documentation: Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: replace-route-table-association](https://docs.aws.amazon.com/cli/latest/reference/ec2/replace-route-table-association.html)