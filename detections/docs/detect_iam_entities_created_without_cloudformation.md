## Overview

Detect IAM entities (users, roles, or groups) created outside of AWS CloudFormation. Manually created entities bypass centralized governance, auditing, and compliance controls, increasing the risk of over-permissioning and misconfigurations. Ensuring these entities are identified helps maintain secure resource management and adherence to infrastructure-as-code (IaC) best practices.

**References**:
- [AWS CloudFormation Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html)
- [Managing IAM Users](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html)
- [AWS CLI Command: create-user](https://docs.aws.amazon.com/cli/latest/reference/iam/create-user.html)
- [AWS CLI Command: create-role](https://docs.aws.amazon.com/cli/latest/reference/iam/create-role.html)
- [AWS CLI Command: create-group](https://docs.aws.amazon.com/cli/latest/reference/iam/create-group.html)

