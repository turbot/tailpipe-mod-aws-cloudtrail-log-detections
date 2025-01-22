## Overview

Detect when an EC2 instance had source/destination checks disabled. While disabling this check is necessary for certain network appliances like NAT instances, it can expose instances to risks such as traffic interception, spoofing, or misuse. Monitoring these instances helps maintain secure network configurations and prevents unauthorized access or data exfiltration.

**References**:
- [Modifying the Source/Destination Check Attribute](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#source-dest-check)
- [Best Practices for Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-best-practices.html)
- [AWS CLI Command: modify-instance-attribute](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/modify-instance-attribute.html)
