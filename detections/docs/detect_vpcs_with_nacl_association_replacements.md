## Overview

Detect Virtual Private Clouds (VPCs) where network ACL (NACL) associations have been replaced. Replacing NACL associations can disrupt traffic flow, potentially exposing subnets to unauthorized access or causing service interruptions. Monitoring these changes helps maintain secure and reliable subnet-level traffic control.

**References**:
- [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: replace-network-acl-association](https://docs.aws.amazon.com/cli/latest/reference/ec2/replace-network-acl-association.html)
