## Overview

Detect AWS CloudTrail trails where logging for AWS Lambda operations is disabled. Disabling Lambda logging reduces visibility into critical activities, such as function creation, modification, or invocation, making it harder to detect unauthorized or malicious actions. Enabling Lambda logging ensures comprehensive monitoring and supports security and compliance efforts.

**References**:
- [AWS Documentation: Logging AWS Lambda API Calls with CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)
- [AWS CLI Command: update-trail](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
