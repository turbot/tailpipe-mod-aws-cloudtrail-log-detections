## Description

This detection identifies security groups within a Virtual Private Cloud (VPC) that have IPv6 rules allowing unrestricted access (::/0) for either ingress or egress traffic. Such configurations expose resources to the entire IPv6 internet, increasing the risk of unauthorized access and potential security breaches.

## Risks

Allowing unrestricted IPv6 access in a security group poses significant security risks. For ingress rules, this can expose resources to unauthorized access, increasing the likelihood of attacks such as brute force attempts, distributed denial-of-service (DDoS), or exploitation of unpatched vulnerabilities. For egress rules, it may allow unrestricted outbound traffic, enabling potential data exfiltration or malicious communication.

Misconfigured or overly permissive IPv6 rules in security groups can lead to severe security incidents, especially in environments that support dual-stack (IPv4 and IPv6) networking. Regular monitoring and remediation of such configurations are essential to maintaining a robust security posture and protecting cloud resources from unauthorized activity.

## References

- [AWS Documentation: Security Groups for Your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- [AWS CLI Command: describe-security-groups](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html)
