## Overview

Detect when a CodeBuild project's visibility was set to public. Publicly accessible projects expose sensitive environments to unauthorized access, increasing the risk of data breaches, malicious builds, or resource abuse. Restricting access to trusted users and roles ensures the security and integrity of build processes.

**References**:
- [Managing Access to CodeBuild Projects](https://docs.aws.amazon.com/codebuild/latest/userguide/auth-and-access-control-iam-access-control-identity-based.html)
- [AWS CLI Command: update-project-visibility](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/codebuild/update-project-visibility.html)