## Description

This detection identifies deletions of routes from route tables within a Virtual Private Cloud (VPC) in an AWS account. Routes in a route table define how network traffic is directed within a VPC. Deleting routes can disrupt network traffic flow and may indicate misconfigurations or unauthorized changes.

## Risks

Deleting routes from a route table can lead to communication failures between resources or with external networks. This can cause service disruptions, particularly for applications relying on specific routing configurations, such as internet access through an internet gateway or private communication with on-premises data centers through a VPN or Direct Connect.

Unauthorized or accidental deletions of routes may expose critical resources to unintended access or isolation, affecting both security and availability. Such changes could also signal malicious activity, where an attacker seeks to disrupt operations or manipulate traffic flow. Without proper monitoring, these actions could go undetected, increasing the risk of operational impact.

## References

- [AWS Documentation: Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: delete-route](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-route.html)