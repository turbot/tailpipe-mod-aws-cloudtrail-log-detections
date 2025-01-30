## Overview

Detect when an AWS Config configuration recorder was stopped. When recording is stopped, resource configuration changes are no longer captured, creating gaps in monitoring and compliance enforcement. Monitoring the recording status ensures continuous tracking of configuration changes and adherence to defined policies.

**References**:
- [AWS Config Configuration Recorder](https://docs.aws.amazon.com/config/latest/developerguide/config-concepts.html#config-recorder)
- [AWS CLI Command: stop-configuration-recorder](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.html)