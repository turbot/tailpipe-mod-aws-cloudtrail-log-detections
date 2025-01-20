## Overview

Detect instances where AWS Key Management Service (KMS) keys are deleted. Deleting a KMS key renders all associated encrypted data inaccessible, leading to data loss, application downtime, and workflow disruptions. Monitoring key deletions ensures data availability, protects sensitive information, and maintains operational continuity.

**References**:
- [AWS Key Management Service (KMS) Keys](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
- [AWS CLI Command: schedule-key-deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html)
- [AWS CLI Command: cancel-key-deletion](https://docs.aws.amazon.com/cli/latest/reference/kms/cancel-key-deletion.html)
