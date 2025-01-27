## Overview

Detect when termination protection was disabled for an EC2 instance. Disabling termination protection increases the risk of accidental or unauthorized termination of critical instances, potentially leading to service disruptions or data loss. Monitoring these changes helps ensure that termination protection remains enabled for critical workloads, maintaining operational continuity and data security.

**References**:
- [Termination Protection for EC2 Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#using-termination-protection)
- [AWS CLI Command: modify-instance-attribute](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/modify-instance-attribute.html)
