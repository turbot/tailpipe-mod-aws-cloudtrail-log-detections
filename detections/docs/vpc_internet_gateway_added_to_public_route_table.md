## Overview

Detect instances where an internet gateway is added to a public route table within a Virtual Private Cloud (VPC). Improper configurations can expose resources to the internet, increasing the risk of unauthorized access, data breaches, or malicious activity. Monitoring these changes ensures secure and intentional network designs.

**References**:
- [Internet Gateways](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html)
- [Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: create-route](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-route.html)
