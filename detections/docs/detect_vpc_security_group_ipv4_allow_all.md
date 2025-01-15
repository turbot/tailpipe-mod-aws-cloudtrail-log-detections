## Overview

Detect modifications to VPC security group rules that allow unrestricted traffic to or from 0.0.0.0/0. Allowing unrestricted access exposes resources to the internet, increasing the risk of unauthorized access, data exfiltration, or exploitation by attackers. Misconfigured or overly permissive security group rules are a common cause of data breaches and security incidents in cloud environments.

**References**:
- [Working with Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- [AWS CLI Command: authorize-security-group-ingress](https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-ingress.html)
- [AWS CLI Command: authorize-security-group-egress](https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-egress.html)
