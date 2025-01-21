## Overview

Detect when a Route 53 domain had its transfer lock disabled. Disabling the transfer lock increases the risk of unauthorized domain transfers, leading to potential loss of domain ownership, service disruptions, or reputational damage. Enabling the transfer lock adds an essential layer of security against accidental or malicious transfers.

**References**:
- [Enabling Domain Transfer Lock](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-lock.html)
- [AWS CLI Command: enable-domain-transfer-lock](https://docs.aws.amazon.com/cli/latest/reference/route53domains/enable-domain-transfer-lock.html)
- [AWS CLI Command: disable-domain-transfer-lock](https://docs.aws.amazon.com/cli/latest/reference/route53domains/disable-domain-transfer-lock.html)
