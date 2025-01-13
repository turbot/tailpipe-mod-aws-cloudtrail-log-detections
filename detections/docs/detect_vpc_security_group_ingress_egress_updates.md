## Description

This detection identifies updates to ingress or egress rules in security groups within a Virtual Private Cloud (VPC) in an AWS account. Security group rules define the allowed inbound and outbound traffic for resources in the VPC. Modifications to these rules can significantly impact the security posture and network behavior.

## Risks

Updating ingress or egress rules in a security group can introduce unintended exposure of resources to unauthorized access or disrupt legitimate communication. For example, adding overly permissive rules may expose resources to the internet, while removing essential rules could block critical application traffic.

Unauthorized or accidental changes to security group rules may indicate mismanagement or malicious intent. An attacker with access to the account could modify rules to allow unauthorized access or facilitate data exfiltration. Without proper monitoring and auditing, these changes could go unnoticed, compromising the security and availability of your resources.

## References

- [AWS Documentation: Security Groups for Your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- [AWS CLI Command: authorize-security-group-ingress](https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-ingress.html)
- [AWS CLI Command: authorize-security-group-egress](https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-egress.html)
- [AWS CLI Command: revoke-security-group-ingress](https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html)
- [AWS CLI Command: revoke-security-group-egress](https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-egress.html)
