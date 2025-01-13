## Description

This detection identifies EC2 instances with source/destination checks disabled. By default, AWS enables source/destination checks on EC2 instances to ensure that the instance is the source or destination of all traffic it handles. Disabling this check is typically required for network appliances such as NAT instances or firewalls but can expose instances to risks if misconfigured or unnecessary.

## Risks

Disabling the source/destination check on EC2 instances can create potential security and operational risks. Instances with this setting disabled can route traffic not intended for them, enabling scenarios such as traffic interception, spoofing, or misuse in malicious activities. Attackers may exploit these instances to conduct lateral movement or man-in-the-middle attacks within your AWS environment.

Furthermore, when source/destination checks are disabled unnecessarily, it can complicate network monitoring and troubleshooting, leading to reduced visibility into traffic flows and increased risk of configuration errors. This misconfiguration can inadvertently expose sensitive systems to unauthorized access or data exfiltration.

Monitoring EC2 instances with source/destination checks disabled helps maintain secure network configurations and prevents the misuse of such instances for malicious activities.

## References

- [AWS Documentation: Modifying the Source/Destination Check Attribute](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#source-dest-check)
- [AWS CLI Command: modify-instance-attribute](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-instance-attribute.html)
- [AWS Documentation: Best Practices for Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-best-practices.html)
