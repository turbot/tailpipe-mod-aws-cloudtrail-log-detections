## Overview

Detect when a Virtual Private Cloud (VPC) internet gateway was added to a public route table. Improper configurations can expose resources to the internet, increasing the risk of unauthorized access, data breaches, or malicious activity. Monitoring these changes ensures secure and intentional network designs.

**References**:
- [Internet Gateways](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html)
- [Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS CLI Command: create-route](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-route.html)
