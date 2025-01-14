## Description

This detection identifies AWS CodeBuild projects that are configured to allow public access. Publicly accessible CodeBuild projects can expose sensitive build environments and configurations, increasing the risk of unauthorized access and potential misuse.

## Risks

Granting public access to CodeBuild projects introduces significant security risks. An attacker with access to a publicly available project could execute malicious builds, expose sensitive environment variables, or modify build configurations. This can lead to data breaches, unauthorized operations, or compromised applications.

Public access may also result in resource abuse, such as running unauthorized workloads on your AWS account, leading to increased costs. Ensuring that CodeBuild projects are restricted to trusted users and roles helps protect sensitive resources and maintain secure build processes.

## References

- [Managing Access to CodeBuild Projects](https://docs.aws.amazon.com/codebuild/latest/userguide/auth-and-access-control-iam-access-control-identity-based.html)
- [AWS CLI Command: update-project-visibility](https://docs.aws.amazon.com/cli/latest/reference/codebuild/update-project-visibility.html)
