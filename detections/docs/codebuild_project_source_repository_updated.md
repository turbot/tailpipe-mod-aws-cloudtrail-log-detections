## Overview

Detect when the source repository configuration of an AWS CodeBuild project was updated. Unauthorized or unintended changes can lead to builds using untrusted or malicious code, disrupting workflows and compromising downstream systems. Monitoring these updates ensures the security and integrity of the build process.

**References**:
- [Source Repository Settings in AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console-source)
- [AWS CLI Command: update-project](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/codebuild/update-project.html)