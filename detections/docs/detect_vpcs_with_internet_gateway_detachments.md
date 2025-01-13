## Description

This detection identifies Virtual Private Clouds (VPCs) where an internet gateway has been detached. Internet gateways are critical for enabling internet connectivity for resources within a VPC. Detachment of an internet gateway can disrupt connectivity and potentially indicate misconfigurations or malicious activity.

## Risks

Detaching an internet gateway from a VPC can result in a loss of internet connectivity for associated resources, leading to disruptions in operations or service availability. This can impact web servers, APIs, or other applications that rely on internet access, particularly in production environments.

Additionally, internet gateway detachments may signal unauthorized or malicious activity within the account. An attacker might detach an internet gateway as part of an effort to isolate resources, disrupt services, or mask malicious actions. Without proper monitoring, these events could compromise the availability and security of your infrastructure.

## References

- [AWS Documentation: Internet Gateways](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html)
- [AWS CLI Command: detach-internet-gateway](https://docs.aws.amazon.com/cli/latest/reference/ec2/detach-internet-gateway.html)