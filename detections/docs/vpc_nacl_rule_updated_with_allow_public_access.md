## Overview

Detect when a Virtual Private Cloud (VPC) network ACL (NACL) rule was updated to allow public access. NACLs are a critical component of VPC security, controlling inbound and outbound traffic at the subnet level. Granting public access to a NACL exposes resources to unauthorized traffic and increases the risk of security breaches.

**References**:
- [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: describe-network-acls](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html)