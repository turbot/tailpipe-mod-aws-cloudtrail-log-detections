## Overview

Detect when an AWS Key Management Service (KMS) key was scheduled for deletion. Scheduling key deletion can render all associated encrypted data inaccessible, leading to data loss, application downtime, and workflow disruptions. Monitoring key deletion schedules ensures data availability, protects sensitive information, and maintains operational continuity.

**References**:
- [AWS Key Management Service (KMS) Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
- [AWS CLI Command: schedule-key-deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)
- [AWS CLI Command: cancel-key-deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/cancel-key-deletion.html)
