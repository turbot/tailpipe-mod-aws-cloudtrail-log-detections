## Description

This detection identifies updates to the source repository configuration of AWS CodeBuild projects. The source repository defines where the build source code originates, such as a specific GitHub repository, Bitbucket, or an S3 bucket. Unauthorized or unintended changes to the source repository can compromise the integrity of the build process and lead to security risks.

## Risks

Updating the source repository for a CodeBuild project without proper oversight can result in builds using untrusted or malicious code. An attacker could redirect the source to a repository containing malicious scripts or unauthorized changes, potentially compromising downstream systems or applications.

In addition, changes to the source repository can disrupt workflows by pointing to incorrect or outdated sources, causing build failures or unexpected behavior. Monitoring updates to source repositories helps ensure that only authorized and verified sources are used, protecting the security and reliability of the build process.

## References

- [Source Repository Settings in AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console-source)
- [AWS CLI Command: update-project](https://docs.aws.amazon.com/cli/latest/reference/codebuild/update-project.html)
