## Overview

Detect when an AWS CloudTrail trail is created without global service logging enabled. Disabling global service logging reduces visibility into critical account activities, such as authentication attempts and IAM changes, potentially compromising account security. Enabling this logging ensures comprehensive monitoring and supports compliance with security best practices.

**References**:
- [AWS Documentation: Logging Global Service Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html)
- [AWS CLI Command: put-event-selectors](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/put-event-selectors.html)