## Overview

Detect deletions of "deny all" rules from network ACLs (NACLs) within a Virtual Private Cloud (VPC). Removing these safeguard rules can expose subnets to unfiltered traffic, increasing the risk of unauthorized access, data exfiltration, or malicious activity. Monitoring NACL configurations ensures the security of VPC resources.

**References**:
- [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [AWS CLI Command: delete-network-acl-entry](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-network-acl-entry.html)
