## Description

This detection identifies instances where an internet gateway is added to a public route table within a Virtual Private Cloud (VPC) in an AWS account. Associating an internet gateway with a public route table enables internet access for resources in the associated subnets. While this is necessary for certain use cases, improper configurations can introduce security risks.

## Risks

Adding an internet gateway to a public route table can inadvertently expose resources in the associated subnets to the internet. If access controls, such as security groups and network ACLs, are not properly configured, this exposure can lead to unauthorized access, data breaches, or malicious activity.

Such configurations may also signal unauthorized or accidental changes, potentially indicating mismanagement or malicious intent. Without continuous monitoring and proper auditing, these actions could compromise the security of sensitive workloads or disrupt critical services. It is essential to ensure that internet gateways are only added to route tables as part of intentional and secure network designs.

## References

- [AWS Documentation: Internet Gateways](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html)
- [AWS Documentation: Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: create-route](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-route.html)
