## Overview

Detect when an Amazon Route 53 hosted zone was associated with an Amazon Virtual Private Cloud (VPC). Unauthorized or improper associations can expose internal DNS records, disrupt DNS resolution, or increase the attack surface. Monitoring these associations ensures private DNS functionality is securely configured and adheres to access control requirements.

**References**:
- [Associating Amazon VPCs with Private Hosted Zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-associate-vpcs.html)
- [Securing Amazon Route 53 Hosted Zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/security.html)
- [AWS CLI Command: associate-vpc-with-hosted-zone](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/route53/associate-vpc-with-hosted-zone.html)
- [AWS CLI Command: disassociate-vpc-from-hosted-zone](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/route53/disassociate-vpc-from-hosted-zone.html)
