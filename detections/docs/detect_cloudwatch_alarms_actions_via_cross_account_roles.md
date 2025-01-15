## Overview

Detect Amazon CloudWatch alarms that invoke actions in other AWS accounts via cross-account IAM roles. Improper configurations or excessive permissions for cross-account actions can lead to unauthorized operations, resource compromise, or privilege escalation. Monitoring these configurations ensures security and proper access control across accounts.

**References**:
- [Amazon CloudWatch cross account alarms](https://aws.amazon.com/about-aws/whats-new/2021/08/announcing-amazon-cloudwatch-cross-account-alarms)
- [AWS CLI Command: put-metric-alarm](https://docs.aws.amazon.com/cli/latest/reference/cloudwatch/put-metric-alarm.html)
