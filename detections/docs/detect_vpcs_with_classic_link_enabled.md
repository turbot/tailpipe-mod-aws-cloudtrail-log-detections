## Description

This detection identifies Virtual Private Clouds (VPCs) with the ClassicLink feature enabled. ClassicLink allows EC2-Classic instances to communicate with VPC resources, but it is a legacy feature that is being deprecated in favor of modern VPC networking practices. Maintaining VPCs with ClassicLink enabled may pose security and operational risks.

## Risks

Enabling ClassicLink on a VPC introduces potential risks due to the legacy nature of the feature. EC2-Classic instances connected via ClassicLink can bypass modern networking controls like security groups and VPC flow logs, making it harder to monitor and secure network traffic. Additionally, reliance on ClassicLink can create technical debt and operational challenges as AWS transitions away from EC2-Classic.

Organizations that continue to use ClassicLink may face difficulties integrating with newer AWS services or implementing best practices for network security and resource isolation. To ensure a secure and scalable cloud environment, it is recommended to migrate workloads away from ClassicLink and fully adopt VPC-based networking.

## References

- [AWS Documentation: ClassicLink](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-classiclink.html)
- [AWS CLI command: enable-vpc-classic-link](https://docs.aws.amazon.com/cli/latest/reference/ec2/enable-vpc-classic-link.html)
