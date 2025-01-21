## Overview

Detect traffic mirror targets associated with internet-facing Network Load Balancers (NLBs). Such configurations expose mirrored traffic to external threats, increasing the risk of data leakage or unauthorized access. Monitoring traffic mirror target associations ensures that mirrored data is directed only to secure, trusted destinations.

**References**:
- [Traffic Mirroring](https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html)
- [Network Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html)
- [AWS CLI Command: describe-traffic-mirror-targets](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-traffic-mirror-targets.html)
