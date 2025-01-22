## Overview

Detect when a store image task for an Amazon Machine Image (AMI) was initiated from an external account. External AMIs may introduce vulnerabilities, malware, or misconfigurations that could compromise your infrastructure. Reviewing and validating these tasks ensures that only trusted and secure AMIs are stored in your environment.

**References**:
- [Exporting an Instance as a VM Using VM Import/Export](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html)
- [Amazon Machine Images (AMIs)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
- [AWS CLI Command: create-store-image-task](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-store-image-task.html)
