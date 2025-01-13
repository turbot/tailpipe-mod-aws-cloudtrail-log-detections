## Description

This detection identifies disassociations of routes from route tables within a Virtual Private Cloud (VPC) in an AWS account. Routes in a route table determine the traffic paths for resources in the VPC. Disassociating a route can disrupt the intended traffic flow and may indicate unauthorized changes or misconfigurations.

## Risks

Disassociating a route from a route table can lead to communication failures within the VPC or between the VPC and external networks. This can disrupt application functionality, prevent access to external services, or isolate critical resources from the internet or private networks.

Unauthorized or accidental route disassociations may expose resources to unintended behavior, such as traffic routing issues or loss of connectivity. This could also indicate malicious activity, where an attacker seeks to modify or disrupt the network routing configuration to isolate resources or interfere with operations. Without continuous monitoring, these changes could compromise the availability and security of the network.

## References

- [AWS Documentation: Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: disassociate-route-table](https://docs.aws.amazon.com/cli/latest/reference/ec2/disassociate-route-table.html)