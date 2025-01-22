## Overview

Detect when a restore image task for an Amazon Machine Image (AMI) was initiated from an external account. Restoring AMIs from untrusted sources may introduce malicious software, insecure configurations, or vulnerabilities, compromising your infrastructure. Monitoring these tasks ensures that only verified and secure AMIs are restored.

**References**:
- [VM Import/Export](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html)
- [Restoring Amazon Machine Images (AMIs)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
- [AWS CLI Command: import-image](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/import-image.html)
