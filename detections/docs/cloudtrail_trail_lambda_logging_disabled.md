## Overview

Detect when an AWS CloudTrail trail is created without Lambda logging enabled. Disabling Lambda logging reduces visibility into critical activities, such as function creation, modification, or invocation, making it harder to detect unauthorized or malicious actions. Enabling Lambda logging ensures comprehensive monitoring and supports security and compliance efforts.

**References**:
- [Logging AWS Lambda API Calls with CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)
- [AWS CLI Command: update-trail](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/update-trail.html)