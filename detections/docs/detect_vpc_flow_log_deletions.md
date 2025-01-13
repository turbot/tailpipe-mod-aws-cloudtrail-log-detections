## Description

This detection identifies the deletion of VPC flow logs in an AWS account. VPC flow logs are a critical resource for monitoring and analyzing network traffic within a VPC. The removal of flow logs can disrupt visibility into network activity, making it harder to detect suspicious or unauthorized behavior.

## Risks

Deleting VPC flow logs without proper oversight can significantly reduce an organization’s ability to monitor network traffic, detect anomalies, and troubleshoot connectivity issues. This lack of visibility increases the risk of undetected security incidents, such as data exfiltration, unauthorized access, or lateral movement within the network.

Additionally, the deletion of flow logs may indicate malicious activity, such as an attacker attempting to evade detection or hide evidence of unauthorized actions. Without continuous monitoring, organizations may lose critical forensic data required for incident response and compliance reporting.

## References

- [AWS Documentation: VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS CLI Command: delete-flow-logs](https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-flow-logs.html)