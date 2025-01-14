## Description

This detection identifies instances where Amazon Elastic Block Store (EBS) volumes are detached from EC2 instances. Monitoring volume detachments is crucial to ensure that critical data remains secure and that unauthorized or accidental actions do not disrupt operations or lead to data loss.

## Risks

Detaching an EBS volume from an EC2 instance without proper authorization can result in operational disruptions, such as application downtime or the unavailability of critical data. If the detached volume contains sensitive or critical information, there is also a risk of data exposure or loss if the volume is not securely managed.

Unauthorized volume detachments may indicate malicious activity, such as an attacker attempting to disrupt services, isolate data, or remove evidence of unauthorized actions. Monitoring volume detachments ensures timely detection of such events and helps maintain the availability, security, and integrity of data stored on EBS volumes.

## References

- [Amazon EBS Volume Attachment](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-attaching-volume.html)
- [AWS CLI Command: detach-volume](https://docs.aws.amazon.com/cli/latest/reference/ec2/detach-volume.html)
