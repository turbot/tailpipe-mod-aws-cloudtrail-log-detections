## Overview

Detect when EC2 spot instances are interrupted or terminated due to capacity reclamation or price changes. Spot instance interruptions occur when AWS needs capacity back or when spot prices exceed the maximum price specified in the request.

Monitoring spot instance interruptions helps identify potential workload disruptions, allowing teams to:
- Verify that applications are handling interruptions gracefully
- Assess the frequency of interruptions to evaluate Spot instance reliability for specific workloads
- Ensure data integrity during unexpected terminations
- Adjust bidding strategies or consider alternative instance types for critical workloads

**References**:
- [EC2 Spot Instance Interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html)
- [Handling Spot Instance Interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-best-practices.html#spot-instance-termination-notices)
- [Spot Instance Advisor](https://aws.amazon.com/ec2/spot/instance-advisor/)
