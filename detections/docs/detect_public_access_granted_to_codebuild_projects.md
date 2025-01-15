## Overview

Detect AWS CodeBuild projects configured to allow public access. Publicly accessible projects expose sensitive environments to unauthorized access, increasing the risk of data breaches, malicious builds, or resource abuse. Restricting access to trusted users and roles ensures the security and integrity of build processes.

**References**:
- [Managing Access to CodeBuild Projects](https://docs.aws.amazon.com/codebuild/latest/userguide/auth-and-access-control-iam-access-control-identity-based.html)
- [AWS CLI Command: update-project-visibility](https://docs.aws.amazon.com/cli/latest/reference/codebuild/update-project-visibility.html)
