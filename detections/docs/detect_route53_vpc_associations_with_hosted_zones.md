## Overview

Detect Amazon Route 53 hosted zones associated with Amazon Virtual Private Clouds (VPCs). Improper or unauthorized associations can expose internal DNS records, disrupt DNS resolution, or increase the attack surface. Monitoring these associations ensures private DNS functionality is securely configured and aligns with access control requirements.

**References**:
- [Associating Amazon VPCs with Private Hosted Zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-associate-vpcs.html)
- [Securing Amazon Route 53 Hosted Zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/security.html)
- [AWS CLI Command: associate-vpc-with-hosted-zone](https://docs.aws.amazon.com/cli/latest/reference/route53/associate-vpc-with-hosted-zone.html)
- [AWS CLI Command: disassociate-vpc-from-hosted-zone](https://docs.aws.amazon.com/cli/latest/reference/route53/disassociate-vpc-from-hosted-zone.html)
