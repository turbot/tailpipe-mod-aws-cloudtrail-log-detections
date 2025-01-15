## Overview

Detect AWS CloudTrail trails with global service event logging disabled. Disabling global service logging reduces visibility into critical account activities, such as authentication attempts and IAM changes, potentially compromising account security. Enabling this logging ensures comprehensive monitoring and supports compliance with security best practices.

**References**:
- [AWS Documentation: Logging Global Service Events](https://jayendrapatil.com/aws-global-vs-regional-vs-az-resources/?utm_content=cmp-true#google_vignette)
- [AWS CLI Command: put-event-selectors](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/put-event-selectors.html)
