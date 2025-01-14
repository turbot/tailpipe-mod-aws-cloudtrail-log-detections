## Description

This detection identifies updates to environment variables in AWS CodeBuild projects. Environment variables in CodeBuild projects often contain configuration details, secrets, or other sensitive information required for the build process. Unauthorized or unintended updates to these variables may compromise the integrity and security of build processes.

## Risks

Updating environment variables in a CodeBuild project can lead to potential security and operational risks. Unauthorized changes may inject malicious scripts, leak sensitive information, or disrupt the build pipeline. For example, replacing or exposing credentials in environment variables can allow attackers to access critical resources or perform unauthorized actions.

Such changes may also result in non-compliance with organizational policies or regulatory standards. Monitoring updates to environment variables ensures that only authorized changes are made, protecting the integrity of the build process and safeguarding sensitive data.

## References

- [Environment Variables in AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html)
- [AWS CLI Command: update-project](https://docs.aws.amazon.com/cli/latest/reference/codebuild/update-project.html)
