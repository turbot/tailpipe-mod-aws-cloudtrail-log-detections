## Overview

Detect when an EC2 instance was launched with a public IP address. Instances with public IP addresses are accessible over the internet, increasing the risk of unauthorized access, brute force attacks, or exposure to other security threats. Monitoring these events helps ensure that public IP addresses are assigned only when necessary and align with security best practices.

**References**:
- [Public IP Addressing in EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#public-ip-addresses)
- [AWS CLI Command: run-instances](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/run-instances.html)
