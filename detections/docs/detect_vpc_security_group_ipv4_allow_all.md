## Description

This detection identifies security groups within a Virtual Private Cloud (VPC) that have IPv4 rules allowing unrestricted access (0.0.0.0/0) for either ingress or egress traffic. Such configurations can expose resources to the entire internet, significantly increasing the risk of unauthorized access.

## Risks

Allowing unrestricted IPv4 access in a security group creates a serious security risk. For ingress rules, this can expose resources to potential attacks from any source, including brute force attempts, malware, and unauthorized access. For egress rules, it may allow unrestricted outbound traffic, which could be exploited for data exfiltration or command-and-control communications in the event of a compromise.

Misconfigured or overly permissive security group rules are a common cause of data breaches and security incidents in cloud environments. Identifying and remediating these configurations is essential to maintaining a strong security posture and protecting sensitive workloads from potential threats.

## References

- [AWS Documentation: Security Groups for Your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- [AWS CLI Command: describe-security-groups](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html)
