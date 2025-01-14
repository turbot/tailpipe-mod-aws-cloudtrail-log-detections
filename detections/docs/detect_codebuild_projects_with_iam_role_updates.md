## Description

This detection identifies updates to the IAM roles associated with AWS CodeBuild projects. IAM roles determine the permissions and access granted to CodeBuild during the build process. Unauthorized or unintended changes to these roles can compromise the security and functionality of the build environment.

## Risks

Updating the IAM role of a CodeBuild project can introduce significant security risks. Assigning an overly permissive role may allow CodeBuild to access sensitive resources it doesn’t require, increasing the risk of data leakage or unauthorized operations. Conversely, assigning an insufficiently permissive role may disrupt build processes by preventing access to necessary resources.

Unauthorized role updates may also indicate malicious activity, such as an attacker attempting to escalate privileges or manipulate resources. Regular monitoring of IAM role changes ensures that only authorized updates are made and that the permissions align with the principle of least privilege.

## References

- [AWS Documentation: Setting Up AWS CodeBuild Service Roles](https://docs.aws.amazon.com/codebuild/latest/userguide/setting-up-service-role.html)
- [AWS CLI Command: update-project](https://docs.aws.amazon.com/cli/latest/reference/codebuild/update-project.html)
