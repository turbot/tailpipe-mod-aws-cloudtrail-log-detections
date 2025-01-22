## Overview

Detect when EC2 instance user data was modified to include the addition of SSH keys. Adding SSH keys via user data may indicate unauthorized attempts to gain persistent access or manipulate instance configurations. Monitoring these changes helps prevent unauthorized access and ensures the integrity of your EC2 environment.

**References**:
- [Instance Metadata and User Data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Best Practices for Securing EC2 Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-best-practices.html)
- [AWS CLI Command: modify-instance-attribute](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/modify-instance-attribute.html)
