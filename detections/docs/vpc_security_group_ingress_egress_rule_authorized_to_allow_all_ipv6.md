## Overview

Detect when a Virtual Private Cloud (VPC) security group was configured with IPv6 rules allowing unrestricted access (::/0) for ingress or egress traffic. Such configurations expose resources to the entire IPv6 internet, increasing the risk of unauthorized access and potential security breaches. Monitoring these rules helps ensure a secure network configuration and prevents unauthorized activity.

**References**:
- [Security Groups for Your VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)
- [AWS CLI Command: describe-security-groups](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/describe-security-groups.html)
