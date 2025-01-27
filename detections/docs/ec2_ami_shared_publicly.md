## Overview

Detect when the launch permission of an Amazon Machine Image (AMI) was modified in your AWS environment. Changes to launch permissions, particularly sharing AMIs with external accounts, can expose sensitive configurations or proprietary software to unauthorized use. Monitoring these changes helps prevent unauthorized access and ensures secure AMI management.

**References**:
- [Sharing AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html)
- [AWS CLI Command: modify-image-attribute](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/modify-image-attribute.html)
