## Description

This detection identifies the creation of new Virtual Private Clouds (VPCs) in an AWS account. Monitoring VPC creation is essential to ensure that new network configurations adhere to security and compliance requirements. Unauthorized or misconfigured VPCs can lead to potential vulnerabilities or mismanagement of resources.

## Risks

The creation of VPCs without proper oversight can introduce security risks, such as the possibility of misconfigured network access controls, overly permissive route tables, or unmonitored internet gateways. These issues can expose critical resources to unauthorized access or allow lateral movement within the network.

Additionally, unplanned VPC creations can lead to operational challenges, such as resource sprawl or overlapping CIDR blocks, which complicate network routing and management. This can result in outages or conflicts when attempting to interconnect VPCs or integrate them into existing network architectures.

## References

- [AWS Documentation: What is Amazon VPC?](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html)
- [AWS CLI Command: create-vpc](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-vpc.html)