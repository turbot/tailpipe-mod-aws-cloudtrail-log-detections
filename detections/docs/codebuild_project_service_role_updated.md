## Overview

Detect when an service role associated with an AWS CodeBuild project was updated. Unauthorized or unintended role changes can grant excessive permissions, disrupt build processes, or expose sensitive resources. Monitoring service role updates ensures permissions align with the principle of least privilege and safeguards the security of build environments.

**References**:
- [Setting Up AWS CodeBuild Service Roles](https://docs.aws.amazon.com/codebuild/latest/userguide/setting-up-service-role.html)
- [AWS CLI Command: update-project](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/codebuild/update-project.html)