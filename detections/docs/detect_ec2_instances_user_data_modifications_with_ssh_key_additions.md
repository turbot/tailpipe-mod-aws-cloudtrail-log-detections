## Description

This detection identifies modifications to EC2 instance user data that include the addition of SSH keys. User data scripts can be used to inject SSH keys during instance initialization, enabling remote access to the instance. Monitoring these changes is critical to detect unauthorized attempts to gain access or manipulate instance configurations.

## Risks

Modifying EC2 instance user data to add SSH keys poses a significant security risk as it may indicate unauthorized attempts to establish persistent access to the instance. If an attacker gains the ability to modify user data, they can inject their own SSH keys to bypass existing access controls, potentially leading to unauthorized access to sensitive data or systems.

Such changes can also expose your environment to compliance risks if they bypass security policies or auditing requirements. Attackers could use these SSH keys for malicious activities such as data exfiltration, lateral movement within your network, or launching attacks on other systems. Monitoring user data modifications ensures the integrity of your EC2 instances and prevents unauthorized access.

## References

- [AWS Documentation: Instance Metadata and User Data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [AWS CLI Command: modify-instance-attribute](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-instance-attribute.html)
- [AWS Documentation: Best Practices for Securing EC2 Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-best-practices.html)
